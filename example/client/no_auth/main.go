package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/tlcp"
)

// 无身份认证 仅用于测试
func main() {
	config := &tlcp.Config{InsecureSkipVerify: true}
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8444", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Hello Go TLCP!"))
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
