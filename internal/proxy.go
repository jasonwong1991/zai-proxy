package internal

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	healthCheckURL      = "https://chat.z.ai/"
	healthCheckInterval = 30 * time.Second
	healthCheckTimeout  = 8 * time.Second
	proxyCooldown       = 60 * time.Second
	maxRetries          = 3
)

var (
	ErrProxyPoolDisabled = errors.New("proxy pool disabled")
	ErrNoHealthyProxy    = errors.New("no healthy proxy available")

	proxyPoolOnce sync.Once
	proxyPool     *ProxyPool
)

type proxyNode struct {
	url            *url.URL
	raw            string
	healthy        atomic.Bool
	unhealthyUntil atomic.Int64
	failCount      atomic.Int32
}

func (n *proxyNode) isHealthy() bool {
	if !n.healthy.Load() {
		return false
	}
	until := n.unhealthyUntil.Load()
	return until == 0 || time.Now().UnixMilli() >= until
}

type ProxyPool struct {
	nodes   []*proxyNode
	cursor  atomic.Uint64
	stopCh  chan struct{}
	stopped atomic.Bool
}

type ProxyTicket struct {
	pool *ProxyPool
	node *proxyNode
}

func InitProxyPool() {
	proxyPoolOnce.Do(func() {
		filePath := os.Getenv("PROXY_FILE")
		if filePath == "" {
			LogInfo("PROXY_FILE not set, proxy pool disabled")
			return
		}

		pool, err := newProxyPool(filePath)
		if err != nil {
			LogError("Failed to init proxy pool: %v", err)
			return
		}

		proxyPool = pool
		LogInfo("Proxy pool enabled with %d nodes", len(pool.nodes))
	})
}

func GetProxyPool() *ProxyPool {
	return proxyPool
}

func ProxyEnabled() bool {
	return proxyPool != nil && len(proxyPool.nodes) > 0
}

func newProxyPool(filePath string) (*ProxyPool, error) {
	nodes, err := loadProxyNodes(filePath)
	if err != nil {
		return nil, err
	}

	pool := &ProxyPool{
		nodes:  nodes,
		stopCh: make(chan struct{}),
	}

	go pool.healthCheckLoop()
	return pool, nil
}

func loadProxyNodes(filePath string) ([]*proxyNode, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open proxy file: %w", err)
	}
	defer file.Close()

	var nodes []*proxyNode
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := url.Parse(line)
		if err != nil {
			LogWarn("Line %d: invalid proxy URL %q: %v", lineNum, line, err)
			continue
		}

		if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5" {
			LogWarn("Line %d: unsupported scheme %q", lineNum, parsed.Scheme)
			continue
		}

		if parsed.Host == "" {
			LogWarn("Line %d: missing host in %q", lineNum, line)
			continue
		}

		node := &proxyNode{
			url: parsed,
			raw: line,
		}
		node.healthy.Store(true)
		nodes = append(nodes, node)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan proxy file: %w", err)
	}

	if len(nodes) == 0 {
		return nil, errors.New("no valid proxy nodes found")
	}

	return nodes, nil
}

func (p *ProxyPool) Close() {
	if p.stopped.CompareAndSwap(false, true) {
		close(p.stopCh)
	}
}

func (p *ProxyPool) healthCheckLoop() {
	p.runHealthChecks()

	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.runHealthChecks()
		case <-p.stopCh:
			return
		}
	}
}

func (p *ProxyPool) runHealthChecks() {
	var wg sync.WaitGroup
	for _, node := range p.nodes {
		wg.Add(1)
		go func(n *proxyNode) {
			defer wg.Done()
			p.checkNode(n)
		}(node)
	}
	wg.Wait()
}

func (p *ProxyPool) checkNode(node *proxyNode) {
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(node.url),
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   healthCheckTimeout,
		ResponseHeaderTimeout: healthCheckTimeout,
	}

	client := &http.Client{
		Timeout:   healthCheckTimeout,
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, healthCheckURL, nil)
	if err != nil {
		return
	}
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		p.markUnhealthy(node, err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		p.markHealthy(node)
	} else {
		p.markUnhealthy(node, fmt.Errorf("status %d", resp.StatusCode))
	}
}

func (p *ProxyPool) markHealthy(node *proxyNode) {
	if !node.healthy.Load() || node.failCount.Load() > 0 {
		LogInfo("Proxy %s recovered", node.url.Host)
	}
	node.healthy.Store(true)
	node.unhealthyUntil.Store(0)
	node.failCount.Store(0)
}

func (p *ProxyPool) markUnhealthy(node *proxyNode, err error) {
	node.failCount.Add(1)
	node.unhealthyUntil.Store(time.Now().Add(proxyCooldown).UnixMilli())
	LogWarn("Proxy %s marked unhealthy (cooldown %s): %v", node.url.Host, proxyCooldown, err)
}

func (p *ProxyPool) nextHealthy() (*proxyNode, error) {
	n := len(p.nodes)
	if n == 0 {
		return nil, ErrNoHealthyProxy
	}

	start := p.cursor.Add(1) - 1
	for i := 0; i < n; i++ {
		idx := (int(start) + i) % n
		node := p.nodes[idx]
		if node.isHealthy() {
			return node, nil
		}
	}

	return nil, ErrNoHealthyProxy
}

func (p *ProxyPool) Acquire(base *http.Transport) (*http.Transport, *ProxyTicket, error) {
	node, err := p.nextHealthy()
	if err != nil {
		return nil, nil, err
	}

	transport := cloneTransport(base)
	transport.Proxy = http.ProxyURL(node.url)

	ticket := &ProxyTicket{pool: p, node: node}
	return transport, ticket, nil
}

func (t *ProxyTicket) Report(err error) {
	if t == nil || t.pool == nil || t.node == nil {
		return
	}
	if err != nil {
		t.pool.markUnhealthy(t.node, err)
	} else {
		t.pool.markHealthy(t.node)
	}
}

func (t *ProxyTicket) ProxyHost() string {
	if t == nil || t.node == nil {
		return ""
	}
	return t.node.url.Host
}

func cloneTransport(base *http.Transport) *http.Transport {
	if base == nil {
		if def, ok := http.DefaultTransport.(*http.Transport); ok {
			return def.Clone()
		}
		return &http.Transport{}
	}
	return base.Clone()
}

func AcquireHTTPClient() (*http.Client, *ProxyTicket) {
	if proxyPool == nil {
		return &http.Client{}, nil
	}

	transport, ticket, err := proxyPool.Acquire(nil)
	if err != nil {
		if !errors.Is(err, ErrNoHealthyProxy) {
			LogWarn("Failed to acquire proxy: %v", err)
		}
		return &http.Client{}, nil
	}

	LogDebug("Using proxy: %s", ticket.ProxyHost())
	return &http.Client{Transport: transport}, ticket
}

func DoRequestWithRetry(req *http.Request) (*http.Response, error) {
	if proxyPool == nil {
		client := &http.Client{}
		return client.Do(req)
	}

	for i := 0; i < maxRetries; i++ {
		client, ticket := AcquireHTTPClient()

		resp, err := client.Do(req)
		if err != nil {
			if ticket != nil {
				ticket.Report(err)
				LogWarn("Request failed via proxy %s (attempt %d/%d): %v",
					ticket.ProxyHost(), i+1, maxRetries, err)
			}

			if req.GetBody != nil {
				req.Body, _ = req.GetBody()
			}
			continue
		}

		if ticket != nil {
			ticket.Report(nil)
		}
		return resp, nil
	}

	LogWarn("All proxy attempts failed, trying direct connection")
	client := &http.Client{}
	return client.Do(req)
}
