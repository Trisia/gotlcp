package main

import (
	"fmt"
	"net"

	"gitee.com/Trisia/gotlcp/dtlcp"
)

func main() {
	config := &dtlcp.Config{InsecureSkipVerify: true}

	// 创建 UDP 连接到服务端
	raw, err := net.Dial("udp", "127.0.0.1:8452")
	if err != nil {
		panic(err)
	}

	// 使用现有 PacketConn 构造 DTLCP 客户端
	conn := dtlcp.Client(raw.(net.PacketConn), raw.RemoteAddr(), config)
	defer conn.Close()
	fmt.Println("DTLCP raw client connected")

	_, err = conn.Write([]byte("Hello from DTLCP raw client!"))
	if err != nil {
		panic(err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("<< %s\n", buf[:n])
}
