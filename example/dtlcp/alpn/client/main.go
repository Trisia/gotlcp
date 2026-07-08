package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

func main() {
	config := &dtlcp.Config{
		InsecureSkipVerify: true,
		// ALPN 应用层协议协商，与服务器一致
		NextProtos: []string{"h2", "http/1.1"},
	}
	conn, err := dtlcp.Dial("udp", "127.0.0.1:8451", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 握手后打印 ALPN 协商结果
	state := conn.ConnectionState()
	fmt.Printf("协商协议: %s\n", state.NegotiatedProtocol)

	_, err = conn.Write([]byte("Hello ALPN Server!"))
	if err != nil {
		panic(err)
	}
	buff := make([]byte, 512)
	n, err := conn.Read(buff)
	if err != nil {
		panic(err)
	}
	fmt.Printf("<< %s\n", buff[:n])
}
