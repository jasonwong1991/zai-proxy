package internal

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	proxyCooldown = 60 * time.Second
	maxRetries    = 3
)

var (
	ErrNoHealthyProxy = errors.New("no healthy proxy available")

	proxyPoolOnce sync.Once
	proxyPool     *ProxyPool
)

type proxyNode struct {
	url            *url.URL
	unhealthyUntil atomic.Int64
}

func (n *proxyNode) isHealthy() bool {
	until := n.unhealthyUntil.Load()
	return until == 0 || time.Now().UnixMilli() >= until
}

type ProxyPool struct {
	nodes  []*proxyNode
	cursor atomic.Uint64
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

func ProxyEnabled() bool {
	return proxyPool != nil && len(proxyPool.nodes) > 0
}

func newProxyPool(filePath string) (*ProxyPool, error) {
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

		nodes = append(nodes, &proxyNode{url: parsed})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan proxy file: %w", err)
	}

	if len(nodes) == 0 {
		return nil, errors.New("no valid proxy nodes found")
	}

	return &ProxyPool{nodes: nodes}, nil
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

func (p *ProxyPool) markUnhealthy(node *proxyNode, err error) {
	node.unhealthyUntil.Store(time.Now().Add(proxyCooldown).UnixMilli())
	LogWarn("Proxy %s marked unhealthy (cooldown %s): %v", node.url.Host, proxyCooldown, err)
}

func (p *ProxyPool) markHealthy(node *proxyNode) {
	node.unhealthyUntil.Store(0)
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

func AcquireHTTPClient() (*http.Client, *ProxyTicket) {
	if proxyPool == nil {
		return &http.Client{}, nil
	}

	node, err := proxyPool.nextHealthy()
	if err != nil {
		return &http.Client{}, nil
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(node.url),
	}

	LogDebug("Using proxy: %s", node.url.Host)
	return &http.Client{Transport: transport}, &ProxyTicket{pool: proxyPool, node: node}
}

func DoRequestWithRetry(req *http.Request) (*http.Response, error) {
	if proxyPool == nil {
		client := NewBrowserHTTPClient()
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
	client := NewBrowserHTTPClient()
	return client.Do(req)
}
