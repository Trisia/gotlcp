package main

import (
	"fmt"
	"gitee.com/Trisia/gotlcp/dtlcp"
	"github.com/emmansun/gmsm/smx509"
)

func main() {
	config := &dtlcp.Config{
		InsecureSkipVerify: true,
		// 自定义证书校验：打印对端证书信息并执行自定义逻辑
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*smx509.Certificate) error {
			fmt.Printf(">>> 客户端自定义校验 - 收到 %d 张对端证书\n", len(rawCerts))
			for i, certDER := range rawCerts {
				cert, err := smx509.ParseCertificate(certDER)
				if err != nil {
					fmt.Printf("解析证书 %d 失败: %v\n", i, err)
					continue
				}
				fmt.Printf("  证书 %d: Subject=%q, Issuer=%q\n", i, cert.Subject.CommonName, cert.Issuer.CommonName)
			}
			return nil
		},
	}
	conn, err := dtlcp.Dial("udp", "127.0.0.1:8449", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Hello Custom Verify Server!"))
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
