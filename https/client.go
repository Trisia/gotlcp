package https

import (
	"context"
	"gitee.com/Trisia/gotlcp/tlcp"
	"net"
	"net/http"
	"time"
)

// NewHTTPSClient 创建TLCP HTTPS客户端
//
// config: TLCP配置参数，不能为空。
//
// TCP连接拨号默认 30秒超时，如你需要设置TCP 各项超时时间请使用  NewHTTPSClientDialer 方法
// TLCP握手超时为 30秒，您可以转换 http.Client.Transport为 *http.Transport 手动设置时间
func NewHTTPSClient(config *tlcp.Config) *http.Client {
	if config == nil {
		return nil
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 60 * time.Second,
	}
	return NewHTTPSClientDialer(dialer, config)
}

// NewHTTPSClientDialer 创建TLCP HTTPS客户端
//
// dialer: 可靠连接的拨号器，可以用于自定义连接超时时间等参数。
// config: TLCP配置参数，不能为空。
// TLCP握手超时为 30秒，您可以转换 http.Client.Transport为 *http.Transport 手动设置时间
func NewHTTPSClientDialer(dialer *net.Dialer, config *tlcp.Config) *http.Client {
	if config == nil || dialer == nil {
		return nil
	}
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := tlcp.Dialer{NetDialer: dialer, Config: config}
				return dialer.DialContext(ctx, network, addr)
			},
			TLSHandshakeTimeout: 30 * time.Second,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}
