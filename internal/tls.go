package internal

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	utls "github.com/refraction-networking/utls"
)

// NewBrowserHTTPClient 创建一个模拟 Chrome TLS 指纹的 HTTP Client
func NewBrowserHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}

				dialer := &net.Dialer{}
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}

				// 使用 Chrome 指纹但强制 HTTP/1.1（不协商 h2）
				spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
				if err != nil {
					conn.Close()
					return nil, err
				}
				// 移除 ALPN 中的 h2，只保留 http/1.1
				for i, ext := range spec.Extensions {
					if alpn, ok := ext.(*utls.ALPNExtension); ok {
						alpn.AlpnProtocols = []string{"http/1.1"}
						spec.Extensions[i] = alpn
						break
					}
				}

				uconn := utls.UClient(conn, &utls.Config{
					ServerName: host,
				}, utls.HelloCustom)
				if err := uconn.ApplyPreset(&spec); err != nil {
					conn.Close()
					return nil, err
				}

				if err := uconn.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}

				return uconn, nil
			},
			TLSClientConfig: &tls.Config{},
		},
	}
}
