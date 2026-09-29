// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"context"
	"sync"
	"testing"
	"time"
)

// dtlcpSessionRound 执行一次握手（用于会话重用测试），返回双方连接状态与错误。
//
// 两次调用必须复用同一对 Config/SessionCache：DTLCP 的会话缓存以对端地址为键，
// 而 mockPacketConn 的地址固定，因此可以稳定命中缓存。
func dtlcpSessionRound(t *testing.T, clientCfg, serverCfg *Config) (clientState, serverState ConnectionState, clientErr, serverErr error) {
	t.Helper()
	clientPConn, serverPConn := newMockPacketConn()
	defer clientPConn.Close()
	defer serverPConn.Close()

	cli := Client(clientPConn, serverPConn.LocalAddr(), clientCfg)
	svr := Server(serverPConn, clientPConn.LocalAddr(), serverCfg)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		serverErr = svr.HandshakeContext(ctx)
		if serverErr == nil {
			serverState = svr.ConnectionState()
		}
	})
	clientErr = cli.HandshakeContext(ctx)
	if clientErr == nil {
		clientState = cli.ConnectionState()
	}
	wg.Wait()
	return clientState, serverState, clientErr, serverErr
}

// TestDTLCPSessionResume 验证 DTLCP 的完整握手与会话重用（X.509 双证书套件）。
//
// 回归点：会话重用时服务端会把 ServerHello 与 CCS/Finished 合并到同一个数据报，
// 客户端不能把数据报中的后续记录当作"连接首记录"做协议识别判定。
func TestDTLCPSessionResume(t *testing.T) {
	certs := initTestCerts()
	clientCache := NewLRUSessionCache(4)
	serverCache := NewLRUSessionCache(4)

	serverCfg := &Config{
		Certificates: []Certificate{certs.sigCert, certs.encCert},
		Time:         time.Now,
		SessionCache: serverCache,
	}
	clientCfg := &Config{
		InsecureSkipVerify: true,
		Time:               time.Now,
		SessionCache:       clientCache,
	}

	firstClient, firstServer, cErr, sErr := dtlcpSessionRound(t, clientCfg, serverCfg)
	if cErr != nil || sErr != nil {
		t.Fatalf("first handshake: client=%v server=%v", cErr, sErr)
	}
	if firstClient.DidResume || firstServer.DidResume {
		t.Fatal("first handshake must not be a resumption")
	}

	secondClient, secondServer, cErr, sErr := dtlcpSessionRound(t, clientCfg, serverCfg)
	if cErr != nil || sErr != nil {
		t.Fatalf("second handshake: client=%v server=%v", cErr, sErr)
	}
	if !secondClient.DidResume {
		t.Fatal("second handshake should resume the session")
	}
	if !secondServer.DidResume {
		t.Fatal("server should report a resumed session")
	}
	if secondClient.CipherSuite != firstClient.CipherSuite {
		t.Fatalf("cipher suite changed on resumption: %04x -> %04x", firstClient.CipherSuite, secondClient.CipherSuite)
	}
}
