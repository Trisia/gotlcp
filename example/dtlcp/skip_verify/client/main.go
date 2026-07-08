package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

func main() {
	config := &dtlcp.Config{InsecureSkipVerify: true}
	conn, err := dtlcp.Dial("udp", "127.0.0.1:8443", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Hello DTLCP Server!"))
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
