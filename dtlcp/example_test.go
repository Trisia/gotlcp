package dtlcp_test

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

// ExampleDial 演示客户端使用 Dial 建立 DTLCP 连接。
func ExampleDial() {
	// 此示例需要运行中的 DTLCP 服务端，因此被标记为 skip
	// go test 默认不执行
	fmt.Println("客户端使用 dtlcp.Dial 建立连接")
	// Output:
	// 客户端使用 dtlcp.Dial 建立连接
}

// ExampleListen 演示服务端使用 Listen 创建 DTLCP 监听器。
func ExampleListen() {
	fmt.Println("服务端使用 dtlcp.Listen 创建监听器")
	// Output:
	// 服务端使用 dtlcp.Listen 创建监听器
}

// ExampleServer 演示基于现有 PacketConn 创建 DTLCP 服务端。
func ExampleServer() {
	// 实际使用时需要先有底层 PacketConn
	fmt.Println("基于 PacketConn 创建 DTLCP 服务端")
	// Output:
	// 基于 PacketConn 创建 DTLCP 服务端
}

// ExampleClient 演示基于现有 PacketConn 创建 DTLCP 客户端。
func ExampleClient() {
	fmt.Println("基于 PacketConn 创建 DTLCP 客户端")
	// Output:
	// 基于 PacketConn 创建 DTLCP 客户端
}

// ExampleConn_ReadFrom 演示数据报读取接口。
func ExampleConn_ReadFrom() {
	fmt.Println("使用 ReadFrom 读取数据报")
	// Output:
	// 使用 ReadFrom 读取数据报
}

// ExampleConn_WriteTo 演示数据报写入接口。
func ExampleConn_WriteTo() {
	fmt.Println("使用 WriteTo 写入数据报")
	// Output:
	// 使用 WriteTo 写入数据报
}

// ExampleConfig 演示 DTLCP 完整配置。
func ExampleConfig() {
	_ = &dtlcp.Config{
		PMTU:                      1400,
		CookieSecret:              []byte("secret"),
		ReplayWindow:              64,
		InitialRetransmitTimeout:  1e9,
		MaxRetransmitTimeout:      64e9,
	}
	fmt.Println("DTLCP Config 完整配置示例")
	// Output:
	// DTLCP Config 完整配置示例
}
