// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"strings"
	"testing"
)

// TestProtocolDetectionRejectsDTLSRecord 验证协议识别启发式仍然拒绝来自
// DTLS 客户端的首条记录（记录版本 >= 0x1000）。
//
// 该判定被限定在连接首记录（epoch=0 且 seq_num=0），以免误伤会话重用时与
// ServerHello 合并在同一数据报中的 ChangeCipherSpec/Finished 记录。
func TestProtocolDetectionRejectsDTLSRecord(t *testing.T) {
	clientPConn, serverPConn := newMockPacketConn()
	defer clientPConn.Close()
	defer serverPConn.Close()

	// DTLS 1.2 记录头：handshake(22) | 0xFEFD | epoch=0 | seq_num=0 | length=0
	dtlsRecord := []byte{22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := clientPConn.WriteTo(dtlsRecord, serverPConn.LocalAddr()); err != nil {
		t.Fatalf("写入伪造记录失败: %v", err)
	}

	svr := Server(serverPConn, clientPConn.LocalAddr(), &Config{})
	if _, err := svr.Read(make([]byte, 16)); err == nil {
		t.Fatal("期望拒绝 DTLS 首记录，但读取成功")
	} else if !strings.Contains(err.Error(), "first record does not look like a TLCP handshake") {
		t.Fatalf("错误信息不符合预期: %v", err)
	}
}
