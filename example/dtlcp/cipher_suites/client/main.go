package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

func main() {
	config := &dtlcp.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			dtlcp.ECC_SM4_GCM_SM3,
			dtlcp.ECDHE_SM4_GCM_SM3,
		},
	}
	conn, err := dtlcp.Dial("udp", "127.0.0.1:8445", config)
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
