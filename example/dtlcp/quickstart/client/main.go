package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

func main() {
	conn, err := dtlcp.Dial("udp", "127.0.0.1:8443", &dtlcp.Config{InsecureSkipVerify: true})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = conn.WriteTo([]byte("Hello DTLCP Server!"), conn.RemoteAddr())
	if err != nil {
		panic(err)
	}
	buff := make([]byte, 516)
	n, addr, err := conn.ReadFrom(buff)
	if err != nil {
		panic(err)
	}
	fmt.Printf(">> %s (来自 %s)\n", buff[:n], addr)
}
