// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

// Conn TLCP 连接对象（桩）
// 完整的定义在 conn.go，后续阶段会覆盖
type Conn struct {
	config *Config
}

// keyAgreementProtocol 密钥协商接口（桩）
// 完整的定义在 key_agreement.go，后续阶段会覆盖
type keyAgreementProtocol interface{}

// eccKeyAgreement SM2密钥交换（桩）
// 完整的定义在 key_agreement.go，后续阶段会覆盖
type eccKeyAgreement struct {
	version uint16
}

// sm2ECDHEKeyAgreement ECDHE SM2密钥交换（桩）
// 完整的定义在 key_agreement.go，后续阶段会覆盖
type sm2ECDHEKeyAgreement struct{}

// serverHandshakeState 服务端握手状态（桩）
// 完整的定义在 handshake_server.go，后续阶段会覆盖
type serverHandshakeState struct{}

// clientHandshakeState 客户端握手状态（桩）
// 完整的定义在 handshake_client.go，后续阶段会覆盖
type clientHandshakeState struct{}

// serverKeyExchangeMsg 服务端密钥交换消息（桩）
// 完整的定义在 handshake_messages.go，后续阶段会覆盖
type serverKeyExchangeMsg struct{}

// clientKeyExchangeMsg 客户端密钥交换消息（桩）
// 完整的定义在 handshake_messages.go，后续阶段会覆盖
type clientKeyExchangeMsg struct{}
