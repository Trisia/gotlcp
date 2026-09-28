package https

import (
	"context"
	"gitee.com/Trisia/gotlcp/tlcp"
	"net"
	"net/http"
	"time"
)

// NewHTTPSClient 创建 TLCP HTTPS 客户端。
//
// 参数：
//   - config：TLCP 配置参数，不能为 nil；为 nil 时直接返回 nil。
//
// 返回值：
//   - *http.Client：使用 TLCP 拨号与握手的 HTTP 客户端；config 为 nil 时返回 nil。
//
// 超时说明：内部固定使用 net.Dialer{Timeout: 30s, KeepAlive: 60s}，该 Timeout 同时约束
// TCP 拨号与 TLCP 握手（握手上下文由它派生），Transport 的空闲连接超时为 30 秒。
// 需要自定义拨号或超时请使用 NewHTTPSClientDialer。
// 注意：Transport 的 TLSHandshakeTimeout 在设置了 DialTLSContext 的 Transport 上不会生效，
// 因此修改它无法调整 TLCP 握手超时，握手超时由传入 dialer 的 Timeout 决定。
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

// NewHTTPSClientDialer 使用指定的拨号器创建 TLCP HTTPS 客户端。
//
// 参数：
//   - dialer：可靠连接的拨号器，可以用于自定义连接超时时间等参数，不能为 nil；为 nil 时直接返回 nil。其 Timeout 同时约束 TCP 拨号与 TLCP 握手。
//   - config：TLCP 配置参数，不能为 nil；为 nil 时直接返回 nil。
//
// 返回值：
//   - *http.Client：通过 http.Transport.DialTLSContext 使用给定拨号器建立 TLCP 连接（含握手）的 HTTP 客户端；
//     dialer 或 config 为 nil 时返回 nil。
//
// 超时说明：Transport 的空闲连接超时为 30 秒；其 TLSHandshakeTimeout 在设置了 DialTLSContext
// 的 Transport 上不会生效，TLCP 握手超时由传入 dialer 的 Timeout 决定（Timeout 为 0 时无超时上限）。
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
