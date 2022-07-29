package main

import (
	"fmt"
	"github.com/Trisia/gotlcp/tlcp"
)

func main() {
	conn, err := tlcp.Dial("tcp", "127.0.0.1:8443", &tlcp.Config{InsecureSkipVerify: true})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	buff := make([]byte, 516)
	n, err := conn.Read(buff)
	if err != nil {
		panic(err)
	}
	fmt.Printf(">> %s\n", buff[:n])
}
