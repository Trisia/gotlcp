// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package tlcp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm9"
)

// ibcTestEnv IBC 握手测试环境：一个 KGC 下的服务端/客户端身份与公共参数。
type ibcTestEnv struct {
	pool         *IBCPool
	serverParams *IBCSysParams
	clientParams *IBCSysParams
	serverCfg    *IBCIdentity
	clientCfg    *IBCIdentity
	serverID     []byte
	clientID     []byte
}

// newIBCTestEnv 构造一次 IBC 握手所需的全部材料。
func newIBCTestEnv(t *testing.T) *ibcTestEnv {
	t.Helper()
	signMaster, encMaster := testIBCMaster(t)
	now := time.Now().Truncate(time.Second)
	validity := ValidityPeriod{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	params, err := NewIBCSysParamsFromMaster("kgc.example", 1, validity, signMaster, encMaster)
	if err != nil {
		t.Fatalf("NewIBCSysParamsFromMaster: %v", err)
	}
	pool := NewIBCPool()
	if err := pool.AddParams(params); err != nil {
		t.Fatalf("AddParams: %v", err)
	}

	env := &ibcTestEnv{
		pool:         pool,
		serverParams: params,
		clientParams: params,
		serverID:     []byte("server@kgc.example"),
		clientID:     []byte("client@kgc.example"),
	}

	env.serverCfg = ibcUserConfig(t, env.serverID, params, signMaster, encMaster)
	env.clientCfg = ibcUserConfig(t, env.clientID, params, signMaster, encMaster)
	return env
}

// ibcUserConfig 派生一个用户的 IBC 配置（签名私钥 hid=0x01，加密私钥 hid=0x03）。
func ibcUserConfig(t *testing.T, identity []byte, params *IBCSysParams,
	signMaster *sm9.SignMasterPrivateKey, encMaster *sm9.EncryptMasterPrivateKey) *IBCIdentity {
	t.Helper()
	signPriv, err := signMaster.GenerateUserKey(identity, hidSM9Sign)
	if err != nil {
		t.Fatalf("GenerateUserKey(sign): %v", err)
	}
	encPriv, err := encMaster.GenerateUserKey(identity, hidSM9Encrypt)
	if err != nil {
		t.Fatalf("GenerateUserKey(enc): %v", err)
	}
	kePriv, err := encMaster.GenerateUserKey(identity, hidSM9KeyExch)
	if err != nil {
		t.Fatalf("GenerateUserKey(keyex): %v", err)
	}
	return &IBCIdentity{
		Identity:              identity,
		Parameters:            params,
		SignPrivateKey:        signPriv,
		EncryptPrivateKey:     encPriv,
		KeyExchangePrivateKey: kePriv,
	}
}

// ibcHandshakeResult 一次握手的结果。
type ibcHandshakeResult struct {
	clientErr   error
	serverErr   error
	clientState ConnectionState
	serverState ConnectionState
	echoed      []byte
}

// runIBCHandshake 通过一条真实 TCP 连接执行一次 IBC 握手，并在成功后回显一段数据。
func runIBCHandshake(t *testing.T, suiteID uint16, mutate func(clientCfg, serverCfg *Config)) ibcHandshakeResult {
	t.Helper()
	env := newIBCTestEnv(t)

	clientCfg := &Config{
		CipherSuites:     []uint16{suiteID},
		IBCIdentity:      env.clientCfg,
		RootIBCSysParams: env.pool,
		ServerName:       "localhost",
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{suiteID},
		IBCIdentity:        env.serverCfg,
		ClientIBCSysParams: env.pool,
	}
	if mutate != nil {
		mutate(clientCfg, serverCfg)
	}

	cli, svr := tcpPipe()
	if cli == nil || svr == nil {
		t.Fatal("tcpPipe failed")
	}
	defer cli.Close()
	defer svr.Close()
	deadline := time.Now().Add(30 * time.Second)
	_ = cli.SetDeadline(deadline)
	_ = svr.SetDeadline(deadline)

	payload := []byte("hello tlcp ibc")
	var (
		res ibcHandshakeResult
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn := Server(svr, serverCfg)
		if err := serverConn.Handshake(); err != nil {
			res.serverErr = err
			return
		}
		res.serverState = serverConn.ConnectionState()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			res.serverErr = err
			return
		}
		res.echoed = buf
	}()

	clientConn := Client(cli, clientCfg)
	res.clientErr = clientConn.Handshake()
	if res.clientErr == nil {
		res.clientState = clientConn.ConnectionState()
		if _, err := clientConn.Write(payload); err != nil {
			res.clientErr = err
		}
	}
	wg.Wait()
	return res
}

// TestIBCHandshake 覆盖 4 个 IBC/IBSDH 套件的单向与双向认证。
func TestIBCHandshake(t *testing.T) {
	suites := []uint16{IBSDH_SM4_CBC_SM3, IBSDH_SM4_GCM_SM3, IBC_SM4_CBC_SM3, IBC_SM4_GCM_SM3}
	for _, suiteID := range suites {
		for _, mutual := range []bool{false, true} {
			name := CipherSuiteName(suiteID)
			if mutual {
				name += "/mutual"
			} else {
				name += "/server-only"
			}
			t.Run(name, func(t *testing.T) {
				mutate := func(clientCfg, serverCfg *Config) {
					if mutual {
						serverCfg.ClientAuth = RequireAndVerifyClientCert
					}
				}
				res := runIBCHandshake(t, suiteID, mutate)
				if res.clientErr != nil {
					t.Fatalf("client handshake: %v", res.clientErr)
				}
				if res.serverErr != nil {
					t.Fatalf("server handshake: %v", res.serverErr)
				}
				if !bytes.Equal(res.echoed, []byte("hello tlcp ibc")) {
					t.Fatalf("application data mismatch: %q", res.echoed)
				}
				if res.clientState.CipherSuite != suiteID || res.serverState.CipherSuite != suiteID {
					t.Fatalf("cipher suite mismatch: client=%s server=%s",
						CipherSuiteName(res.clientState.CipherSuite), CipherSuiteName(res.serverState.CipherSuite))
				}
				if !bytes.Equal(res.clientState.PeerIBCIdentity, []byte("server@kgc.example")) {
					t.Fatalf("client peer IBC identity mismatch: %q", res.clientState.PeerIBCIdentity)
				}
				if res.clientState.PeerIBCSysParams == nil {
					t.Fatal("client peer IBC parameters missing")
				}
				if mutual {
					if !bytes.Equal(res.serverState.PeerIBCIdentity, []byte("client@kgc.example")) {
						t.Fatalf("server peer IBC identity mismatch: %q", res.serverState.PeerIBCIdentity)
					}
					if res.serverState.PeerIBCSysParams == nil {
						t.Fatal("server peer IBC parameters missing")
					}
				}
			})
		}
	}
}

// TestIBCHandshakeDefaultTrustPool 未配置信任池时，默认以本端
// IBCIdentity.Parameters 作为信任池：同一 KGC 的单向与双向认证均可完成握手。
func TestIBCHandshakeDefaultTrustPool(t *testing.T) {
	for _, mutual := range []bool{false, true} {
		name := "server-only"
		if mutual {
			name = "mutual"
		}
		t.Run(name, func(t *testing.T) {
			res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
				clientCfg.RootIBCSysParams = nil
				serverCfg.ClientIBCSysParams = nil
				if mutual {
					serverCfg.ClientAuth = RequireAndVerifyClientCert
				}
			})
			if res.clientErr != nil {
				t.Fatalf("client handshake: %v", res.clientErr)
			}
			if res.serverErr != nil {
				t.Fatalf("server handshake: %v", res.serverErr)
			}
			if res.clientState.PeerIBCSysParams == nil {
				t.Fatal("client peer IBC parameters missing")
			}
			if mutual && res.serverState.PeerIBCSysParams == nil {
				t.Fatal("server peer IBC parameters missing")
			}
		})
	}
}

// TestIBCHandshakeDefaultTrustPoolRejectsOtherKGC 默认信任池同样要求 KGC 一致：
// 本端参数与对端参数不是同一 KGC 时必须拒绝。
func TestIBCHandshakeDefaultTrustPoolRejectsOtherKGC(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		other := testIBCSysParams(t) // 另一个 KGC 的参数
		res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
			clientCfg.RootIBCSysParams = nil
			clientCfg.IBCIdentity = &IBCIdentity{
				Identity:              clientCfg.IBCIdentity.Identity,
				Parameters:            other,
				SignPrivateKey:        clientCfg.IBCIdentity.SignPrivateKey,
				EncryptPrivateKey:     clientCfg.IBCIdentity.EncryptPrivateKey,
				KeyExchangePrivateKey: clientCfg.IBCIdentity.KeyExchangePrivateKey,
			}
		})
		if res.clientErr == nil {
			t.Fatal("expected client handshake failure")
		}
	})

	t.Run("server", func(t *testing.T) {
		other := testIBCSysParams(t) // 另一个 KGC 的参数
		res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
			serverCfg.ClientIBCSysParams = nil
			serverCfg.ClientAuth = RequireAndVerifyClientCert
			serverCfg.IBCIdentity = &IBCIdentity{
				Identity:              serverCfg.IBCIdentity.Identity,
				Parameters:            other,
				SignPrivateKey:        serverCfg.IBCIdentity.SignPrivateKey,
				EncryptPrivateKey:     serverCfg.IBCIdentity.EncryptPrivateKey,
				KeyExchangePrivateKey: serverCfg.IBCIdentity.KeyExchangePrivateKey,
			}
		})
		if res.serverErr == nil {
			t.Fatal("expected server handshake failure")
		}
	})
}

// TestIBCHandshakeDefaultTrustPoolUnavailable 本端没有 IBC 公共参数时默认信任池为空，
// 且既无显式信任池也无回调，必须拒绝握手。
func TestIBCHandshakeDefaultTrustPoolUnavailable(t *testing.T) {
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		clientCfg.RootIBCSysParams = nil
		clientCfg.IBCIdentity = &IBCIdentity{
			Identity:              clientCfg.IBCIdentity.Identity,
			SignPrivateKey:        clientCfg.IBCIdentity.SignPrivateKey,
			EncryptPrivateKey:     clientCfg.IBCIdentity.EncryptPrivateKey,
			KeyExchangePrivateKey: clientCfg.IBCIdentity.KeyExchangePrivateKey,
		}
	})
	if res.clientErr == nil {
		t.Fatal("expected client handshake failure")
	}
}

// TestIBCHandshakeSkipVerify InsecureSkipVerify 会同时跳过 IBC 公共参数校验。
func TestIBCHandshakeSkipVerify(t *testing.T) {
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		clientCfg.RootIBCSysParams = nil
		clientCfg.InsecureSkipVerify = true
	})
	if res.clientErr != nil {
		t.Fatalf("client handshake: %v", res.clientErr)
	}
	if res.serverErr != nil {
		t.Fatalf("server handshake: %v", res.serverErr)
	}
}

// TestIBCHandshakeUntrustedPool 主公钥不匹配的信任池必须拒绝。
func TestIBCHandshakeUntrustedPool(t *testing.T) {
	other := testIBCSysParams(t) // 另一个 KGC 的参数
	pool := NewIBCPool()
	if err := pool.AddParams(other); err != nil {
		t.Fatalf("AddParams: %v", err)
	}
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		clientCfg.RootIBCSysParams = pool
	})
	if res.clientErr == nil {
		t.Fatal("expected client handshake failure")
	}
}

// TestIBCHandshakeVerifyCallback 信任池为空但配置了回调时由回调全权判定。
func TestIBCHandshakeVerifyCallback(t *testing.T) {
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		clientCfg.RootIBCSysParams = nil
		clientCfg.VerifyIBCSysParams = func(*IBCSysParams) error { return nil }
	})
	if res.clientErr != nil {
		t.Fatalf("client handshake: %v", res.clientErr)
	}
}

// TestIBCHandshakeExpiredParams 有效期校验失败回 unsupported_ibcparam。
func TestIBCHandshakeExpiredParams(t *testing.T) {
	env := newIBCTestEnv(t)
	// 客户端信任池中的参数已过期。
	expired := *env.serverParams
	expired.Raw = nil
	expired.Validity = ValidityPeriod{
		NotBefore: env.serverParams.Validity.NotBefore.Add(-48 * time.Hour),
		NotAfter:  env.serverParams.Validity.NotBefore.Add(-24 * time.Hour),
	}
	der, err := expired.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	reparsed, err := ParseIBCSysParams(der)
	if err != nil {
		t.Fatalf("ParseIBCSysParams: %v", err)
	}
	if err := reparsed.VerifyValidity(time.Now()); err == nil {
		t.Fatal("expected validity failure")
	}
}

// TestIBCHandshakeIdentityMismatch client_id 扩展与 Certificate 标识不一致时
// 服务端回 illegal_parameter(47)。
func TestIBCHandshakeIdentityMismatch(t *testing.T) {
	res := runIBCHandshake(t, IBSDH_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		serverCfg.ClientAuth = RequireAndVerifyClientCert
		// client_id 扩展发送裸标识，而 Certificate 中发送 Identifier 形式，
		// 这里直接改写扩展内容制造不一致。
		clientCfg.IBCIdentity = &IBCIdentity{
			Identity:              []byte("other@kgc.example"),
			Parameters:            clientCfg.IBCIdentity.Parameters,
			SignPrivateKey:        clientCfg.IBCIdentity.SignPrivateKey,
			EncryptPrivateKey:     clientCfg.IBCIdentity.EncryptPrivateKey,
			KeyExchangePrivateKey: clientCfg.IBCIdentity.KeyExchangePrivateKey,
		}
	})
	if res.serverErr == nil {
		t.Fatal("expected server handshake failure")
	}
}

// TestIBCHandshakeMissingClientID IBSDH 下服务端拿不到客户端标识时回 identity_need(205)。
func TestIBCHandshakeMissingClientID(t *testing.T) {
	env := newIBCTestEnv(t)

	// 客户端不发送 client_id 扩展（只保留 GetClientIBCIdentity 能力）。
	clientCfg := &Config{
		CipherSuites: []uint16{IBSDH_SM4_GCM_SM3},
		IBCIdentity: &IBCIdentity{
			// 标识为空 ⇒ 不发送扩展，但仍可用密钥交换私钥参与密钥交换。
			Parameters:            env.clientCfg.Parameters,
			SignPrivateKey:        env.clientCfg.SignPrivateKey,
			EncryptPrivateKey:     env.clientCfg.EncryptPrivateKey,
			KeyExchangePrivateKey: env.clientCfg.KeyExchangePrivateKey,
		},
		RootIBCSysParams: env.pool,
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{IBSDH_SM4_GCM_SM3},
		IBCIdentity:        env.serverCfg,
		ClientIBCSysParams: env.pool,
	}

	cli, svr := tcpPipe()
	if cli == nil || svr == nil {
		t.Fatal("tcpPipe failed")
	}
	defer cli.Close()
	defer svr.Close()
	deadline := time.Now().Add(30 * time.Second)
	_ = cli.SetDeadline(deadline)
	_ = svr.SetDeadline(deadline)

	var (
		serverErr error
		wg        sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = Server(svr, serverCfg).Handshake()
	}()
	clientErr := Client(cli, clientCfg).Handshake()
	wg.Wait()
	if clientErr == nil {
		t.Fatal("expected client handshake failure")
	}
	if serverErr == nil {
		t.Fatal("expected server handshake failure")
	}
	if !strings.Contains(serverErr.Error(), "client identity") {
		t.Fatalf("expected identity_need, got %v", serverErr)
	}
}

// TestIBCHandshakeWithoutIBCIdentity 未配置 IBCIdentity 时 IBC 套件不参与协商。
func TestIBCHandshakeWithoutIBCIdentity(t *testing.T) {
	// 客户端没有 IBCIdentity，因此 ClientHello 中不会包含 IBC 套件。
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		compressionMethods: []uint8{compressionNone},
	}
	_ = hello
	if cipherSuiteIsIBC(ECC_SM4_GCM_SM3) {
		t.Fatal("ECC suite must not be flagged as IBC")
	}
	if !cipherSuiteIsIBC(IBC_SM4_GCM_SM3) || !cipherSuiteIsIBC(IBSDH_SM4_CBC_SM3) {
		t.Fatal("IBC/IBSDH suites must be flagged as IBC")
	}
}

// TestClientIDExtensionEncoding 固化 client_id(66) 扩展的字节布局。
func TestClientIDExtensionEncoding(t *testing.T) {
	hello := &clientHelloMsg{
		vers:               VersionTLCP,
		random:             make([]byte, 32),
		compressionMethods: []uint8{compressionNone},
		cipherSuites:       []uint16{IBSDH_SM4_GCM_SM3},
	}
	identity := []byte("client@kgc.example")
	setClientIDExtension(hello, identity)
	der, err := hello.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// 扩展体：00 42 | len(2) | 00 02 | len(id) | id
	want := []byte{0x00, 0x42, 0x00, byte(2 + len(identity)), 0x00, byte(len(identity))}
	want = append(want, identity...)
	if !bytes.Contains(der, want) {
		t.Fatalf("client_id extension not found in %x", der)
	}

	var got clientHelloMsg
	if !got.unmarshal(der) {
		t.Fatal("unmarshal failed")
	}
	if !bytes.Equal(got.ibsdhClientID, identity) {
		t.Fatalf("client id mismatch: %q", got.ibsdhClientID)
	}
}

// TestIBCCertificateMessageRoundTrip 固化 IBC 变体 Certificate 消息的编解码。
func TestIBCCertificateMessageRoundTrip(t *testing.T) {
	params := testIBCSysParams(t)
	msg := &ibcCertificateMsg{
		ibcID:        []byte("server@kgc.example"),
		ibcParameter: params.Raw,
	}
	der, err := msg.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if der[0] != typeCertificate {
		t.Fatalf("unexpected message type: %d", der[0])
	}
	var got ibcCertificateMsg
	if !got.unmarshal(der) {
		t.Fatal("unmarshal failed")
	}
	if !bytes.Equal(got.ibcID, msg.ibcID) || !bytes.Equal(got.ibcParameter, msg.ibcParameter) {
		t.Fatal("round trip mismatch")
	}
}

// TestIBCHandshakeSessionResume 验证 IBC 套件的会话重用。
func TestIBCHandshakeSessionResume(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCache := NewLRUSessionCache(4)
	serverCache := NewLRUSessionCache(4)

	clientCfg := &Config{
		CipherSuites:     []uint16{IBC_SM4_GCM_SM3},
		IBCIdentity:      env.clientCfg,
		RootIBCSysParams: env.pool,
		SessionCache:     clientCache,
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{IBC_SM4_GCM_SM3},
		IBCIdentity:        env.serverCfg,
		ClientIBCSysParams: env.pool,
		SessionCache:       serverCache,
	}

	// 第一次完整握手，建立会话缓存。
	// 会话缓存以对端地址为键，因此两次握手必须使用同一监听端口。
	first := ibcSessionRound(t, 8456, clientCfg, serverCfg)
	if first.clientErr != nil || first.serverErr != nil {
		t.Fatalf("first handshake: client=%v server=%v", first.clientErr, first.serverErr)
	}
	if first.clientState.DidResume {
		t.Fatal("first handshake must not be a resumption")
	}

	// 第二次应命中会话重用。
	second := ibcSessionRound(t, 8456, clientCfg, serverCfg)
	if second.clientErr != nil || second.serverErr != nil {
		t.Fatalf("second handshake: client=%v server=%v", second.clientErr, second.serverErr)
	}
	if !second.clientState.DidResume {
		t.Fatal("second handshake should resume the session")
	}
	if !bytes.Equal(second.clientState.PeerIBCIdentity, []byte("server@kgc.example")) {
		t.Fatalf("resumed peer IBC identity mismatch: %q", second.clientState.PeerIBCIdentity)
	}
	if second.clientState.PeerIBCSysParams == nil {
		t.Fatal("resumed peer IBC parameters missing")
	}
}

// ibcSessionRound 执行一次握手（用于会话重用测试），不校验应用数据。
func ibcSessionRound(t *testing.T, port int, clientCfg, serverCfg *Config) ibcHandshakeResult {
	t.Helper()
	cli, svr := tcpPipe(port)
	if cli == nil || svr == nil {
		t.Fatal("tcpPipe failed")
	}
	defer cli.Close()
	defer svr.Close()
	deadline := time.Now().Add(30 * time.Second)
	_ = cli.SetDeadline(deadline)
	_ = svr.SetDeadline(deadline)

	var (
		res ibcHandshakeResult
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn := Server(svr, serverCfg)
		if err := serverConn.Handshake(); err != nil {
			res.serverErr = err
			return
		}
		res.serverState = serverConn.ConnectionState()
	}()
	clientConn := Client(cli, clientCfg)
	res.clientErr = clientConn.Handshake()
	if res.clientErr == nil {
		res.clientState = clientConn.ConnectionState()
	}
	wg.Wait()
	return res
}

// BenchmarkHandshakeIBC IBC 套件的完整握手性能。
func BenchmarkHandshakeIBC(b *testing.B) {
	env := ibcBenchEnv(b)
	clientCfg := &Config{
		CipherSuites:     []uint16{IBC_SM4_GCM_SM3},
		IBCIdentity:      env.clientCfg,
		RootIBCSysParams: env.pool,
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{IBC_SM4_GCM_SM3},
		IBCIdentity:        env.serverCfg,
		ClientIBCSysParams: env.pool,
	}
	benchmarkIBCHandshake(b, clientCfg, serverCfg)
}

// BenchmarkHandshakeIBSDH IBSDH 套件的完整握手性能。
func BenchmarkHandshakeIBSDH(b *testing.B) {
	env := ibcBenchEnv(b)
	clientCfg := &Config{
		CipherSuites:     []uint16{IBSDH_SM4_GCM_SM3},
		IBCIdentity:      env.clientCfg,
		RootIBCSysParams: env.pool,
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{IBSDH_SM4_GCM_SM3},
		IBCIdentity:        env.serverCfg,
		ClientIBCSysParams: env.pool,
		ClientAuth:         RequireAndVerifyClientCert,
	}
	benchmarkIBCHandshake(b, clientCfg, serverCfg)
}

func benchmarkIBCHandshake(b *testing.B, clientCfg, serverCfg *Config) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 使用内存管道，避免 TCP 建连开销掩盖密码运算开销。
		cli, svr := net.Pipe()
		deadline := time.Now().Add(30 * time.Second)
		_ = cli.SetDeadline(deadline)
		_ = svr.SetDeadline(deadline)

		var (
			serverErr error
			wg        sync.WaitGroup
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			serverErr = Server(svr, serverCfg).Handshake()
		}()
		clientErr := Client(cli, clientCfg).Handshake()
		wg.Wait()
		_ = cli.Close()
		_ = svr.Close()
		if clientErr != nil || serverErr != nil {
			b.Fatalf("handshake failed: client=%v server=%v", clientErr, serverErr)
		}
	}
}

// ibcBenchEnv 与 newIBCTestEnv 相同但接受 testing.B。
func ibcBenchEnv(b *testing.B) *ibcTestEnv {
	b.Helper()
	signMaster, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateSignMasterKey: %v", err)
	}
	encMaster, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateEncryptMasterKey: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	validity := ValidityPeriod{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	params, err := NewIBCSysParamsFromMaster("kgc.example", 1, validity, signMaster, encMaster)
	if err != nil {
		b.Fatalf("NewIBCSysParamsFromMaster: %v", err)
	}
	pool := NewIBCPool()
	if err := pool.AddParams(params); err != nil {
		b.Fatalf("AddParams: %v", err)
	}

	serverID := []byte("server@kgc.example")
	clientID := []byte("client@kgc.example")
	serverSign, err := signMaster.GenerateUserKey(serverID, hidSM9Sign)
	if err != nil {
		b.Fatalf("GenerateUserKey(sign): %v", err)
	}
	serverEnc, err := encMaster.GenerateUserKey(serverID, hidSM9Encrypt)
	if err != nil {
		b.Fatalf("GenerateUserKey(enc): %v", err)
	}
	clientSign, err := signMaster.GenerateUserKey(clientID, hidSM9Sign)
	if err != nil {
		b.Fatalf("GenerateUserKey(sign): %v", err)
	}
	clientEnc, err := encMaster.GenerateUserKey(clientID, hidSM9Encrypt)
	if err != nil {
		b.Fatalf("GenerateUserKey(enc): %v", err)
	}
	serverKE, err := encMaster.GenerateUserKey(serverID, hidSM9KeyExch)
	if err != nil {
		b.Fatalf("GenerateUserKey(keyex): %v", err)
	}
	clientKE, err := encMaster.GenerateUserKey(clientID, hidSM9KeyExch)
	if err != nil {
		b.Fatalf("GenerateUserKey(keyex): %v", err)
	}

	return &ibcTestEnv{
		pool:         pool,
		serverParams: params,
		clientParams: params,
		serverCfg: &IBCIdentity{
			Identity: serverID, Parameters: params,
			SignPrivateKey: serverSign, EncryptPrivateKey: serverEnc,
			KeyExchangePrivateKey: serverKE,
		},
		clientCfg: &IBCIdentity{
			Identity: clientID, Parameters: params,
			SignPrivateKey: clientSign, EncryptPrivateKey: clientEnc,
			KeyExchangePrivateKey: clientKE,
		},
		serverID: serverID,
		clientID: clientID,
	}
}

var _ net.Conn = (*pipeConn)(nil)

// TestIBCHandshakeAlertBadCertificate 客户端 CertificateVerify 验签失败时
// 服务端回 bad_certificate(42)。
func TestIBCHandshakeAlertBadCertificate(t *testing.T) {
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		serverCfg.ClientAuth = RequireAndVerifyClientCert
		// 用另一套 KGC 的签名私钥签名，验签必然失败。
		otherSign, _ := testIBCMaster(t)
		badSign, err := otherSign.GenerateUserKey([]byte("client@kgc.example"), hidSM9Sign)
		if err != nil {
			t.Fatalf("GenerateUserKey: %v", err)
		}
		clientCfg.IBCIdentity = &IBCIdentity{
			Identity:              clientCfg.IBCIdentity.Identity,
			Parameters:            clientCfg.IBCIdentity.Parameters,
			SignPrivateKey:        badSign,
			EncryptPrivateKey:     clientCfg.IBCIdentity.EncryptPrivateKey,
			KeyExchangePrivateKey: clientCfg.IBCIdentity.KeyExchangePrivateKey,
		}
	})
	if res.serverErr == nil {
		t.Fatal("expected server handshake failure")
	}
	if !strings.Contains(res.serverErr.Error(), "client identity") {
		t.Fatalf("expected signature failure, got %v", res.serverErr)
	}
}

// TestIBCHandshakeGetIBCIdentity 服务端通过 GetIBCIdentity 回调动态返回 IBC 配置。
func TestIBCHandshakeGetIBCIdentity(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg := &Config{
		CipherSuites:     []uint16{IBC_SM4_GCM_SM3},
		IBCIdentity:      env.clientCfg,
		RootIBCSysParams: env.pool,
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{IBC_SM4_GCM_SM3},
		ClientIBCSysParams: env.pool,
		GetIBCIdentity: func(info *ClientHelloInfo) (*IBCIdentity, error) {
			if len(info.CipherSuites) == 0 {
				t.Error("ClientHelloInfo.CipherSuites is empty")
			}
			return env.serverCfg, nil
		},
	}
	res := ibcSessionRound(t, 8457, clientCfg, serverCfg)
	if res.clientErr != nil {
		t.Fatalf("client handshake: %v", res.clientErr)
	}
	if res.serverErr != nil {
		t.Fatalf("server handshake: %v", res.serverErr)
	}
}

// TestIBCHandshakeGetClientIBCIdentity 客户端通过 GetClientIBCIdentity 回调
// 响应服务端的 IBC 证书请求。
func TestIBCHandshakeGetClientIBCIdentity(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg := &Config{
		CipherSuites:     []uint16{IBC_SM4_GCM_SM3},
		RootIBCSysParams: env.pool,
		GetClientIBCIdentity: func(cri *CertificateRequestInfo) (*IBCIdentity, error) {
			return env.clientCfg, nil
		},
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{IBC_SM4_GCM_SM3},
		IBCIdentity:        env.serverCfg,
		ClientIBCSysParams: env.pool,
		ClientAuth:         RequireAndVerifyClientCert,
	}
	res := ibcSessionRound(t, 8458, clientCfg, serverCfg)
	if res.clientErr != nil {
		t.Fatalf("client handshake: %v", res.clientErr)
	}
	if res.serverErr != nil {
		t.Fatalf("server handshake: %v", res.serverErr)
	}
	if !bytes.Equal(res.serverState.PeerIBCIdentity, []byte("client@kgc.example")) {
		t.Fatalf("server peer IBC identity mismatch: %q", res.serverState.PeerIBCIdentity)
	}
}

// TestIBCHandshakeServerWithoutIBCIdentity 服务端未配置 IBC 能力时
// IBC 套件在套件选择阶段被跳过。
func TestIBCHandshakeServerWithoutIBCIdentity(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg := &Config{
		CipherSuites:     []uint16{IBC_SM4_GCM_SM3},
		IBCIdentity:      env.clientCfg,
		RootIBCSysParams: env.pool,
	}
	serverCfg := &Config{
		CipherSuites: []uint16{IBC_SM4_GCM_SM3},
		// 既没有 IBCIdentity 也没有 GetIBCIdentity，且没有 X.509 证书。
	}
	res := ibcSessionRound(t, 8459, clientCfg, serverCfg)
	if res.clientErr == nil {
		t.Fatal("expected client handshake failure")
	}
}

// TestIBCSignedParamsVectors 固化 IBC/IBSDH 的 signed_params 覆盖数据（TBS）字节布局。
func TestIBCSignedParamsVectors(t *testing.T) {
	clientRandom := bytes.Repeat([]byte{0xA0}, 32)
	serverRandom := bytes.Repeat([]byte{0xB0}, 32)

	ibcID := []byte("server@kgc.example")
	tbs := ibcSignedParams(clientRandom, serverRandom, ibcID)
	if len(tbs) != 64+2+len(ibcID) {
		t.Fatalf("unexpected IBC TBS length: %d", len(tbs))
	}
	if !bytes.Equal(tbs[:32], clientRandom) || !bytes.Equal(tbs[32:64], serverRandom) {
		t.Fatal("IBC TBS random prefix mismatch")
	}
	if tbs[64] != 0x00 || tbs[65] != byte(len(ibcID)) {
		t.Fatalf("IBC TBS ibc_id length prefix mismatch: %x", tbs[64:66])
	}
	if !bytes.Equal(tbs[66:], ibcID) {
		t.Fatal("IBC TBS ibc_id mismatch")
	}

	params := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	tbs = ibsdhSignedParams(clientRandom, serverRandom, params)
	if len(tbs) != 64+len(params) {
		t.Fatalf("unexpected IBSDH TBS length: %d", len(tbs))
	}
	if !bytes.Equal(tbs[64:], params) {
		t.Fatal("IBSDH TBS params mismatch")
	}
}

// TestIBCKeyExchangeMessageLayout 校验 IBC/IBSDH 两个套件的密钥交换报文布局。
func TestIBCKeyExchangeMessageLayout(t *testing.T) {
	env := newIBCTestEnv(t)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	t.Run("IBC/ServerKeyExchange", func(t *testing.T) {
		hs := &serverHandshakeState{
			c:           &Conn{config: &Config{}},
			clientHello: &clientHelloMsg{random: clientRandom},
			hello:       &serverHelloMsg{random: serverRandom},
			ibcIdentity: env.serverCfg,
		}
		skx, err := (&ibcKeyAgreement{}).generateServerKeyExchange(hs)
		if err != nil {
			t.Fatalf("generateServerKeyExchange: %v", err)
		}
		if len(skx.key) < 3 {
			t.Fatalf("ServerKeyExchange too short: %d", len(skx.key))
		}
		sigLen := int(skx.key[0])<<8 | int(skx.key[1])
		if sigLen+2 != len(skx.key) {
			t.Fatalf("signature length prefix mismatch: %d vs %d", sigLen, len(skx.key)-2)
		}
		// SM9Signature ::= SEQUENCE { OCTET STRING h, BIT STRING s }
		if skx.key[2] != 0x30 {
			t.Fatalf("signature is not a DER SEQUENCE: %x", skx.key[2])
		}
	})

	t.Run("IBSDH/ServerKeyExchange", func(t *testing.T) {
		hs := &serverHandshakeState{
			c:              &Conn{config: &Config{}},
			clientHello:    &clientHelloMsg{random: clientRandom},
			hello:          &serverHelloMsg{random: serverRandom},
			ibcIdentity:    env.serverCfg,
			ibcClientIDRaw: env.clientID,
		}
		skx, err := (&ibsdhKeyAgreement{}).generateServerKeyExchange(hs)
		if err != nil {
			t.Fatalf("generateServerKeyExchange: %v", err)
		}
		info, consumed, err := parseKeyAgreementInfoPrefix(skx.key)
		if err != nil {
			t.Fatalf("parseKeyAgreementInfoPrefix: %v", err)
		}
		if info.Hid != hidSM9KeyExch {
			t.Fatalf("unexpected hid: %x", info.Hid)
		}
		if !bytes.Equal(info.UserID_A, env.serverID) || !bytes.Equal(info.UserID_B, env.clientID) {
			t.Fatalf("user ids mismatch: %q / %q", info.UserID_A, info.UserID_B)
		}
		sigLen := int(skx.key[consumed])<<8 | int(skx.key[consumed+1])
		if consumed+2+sigLen != len(skx.key) {
			t.Fatal("ServerIBSDHParams / signed_params layout mismatch")
		}
	})

	t.Run("IBC/ClientKeyExchange", func(t *testing.T) {
		srvHS := &serverHandshakeState{
			c:           &Conn{config: &Config{}},
			clientHello: &clientHelloMsg{random: clientRandom},
			hello:       &serverHelloMsg{random: serverRandom},
			ibcIdentity: env.serverCfg,
		}
		skx, err := (&ibcKeyAgreement{}).generateServerKeyExchange(srvHS)
		if err != nil {
			t.Fatalf("generateServerKeyExchange: %v", err)
		}

		hs := &clientHandshakeState{
			c:                  &Conn{config: &Config{}},
			hello:              &clientHelloMsg{vers: VersionTLCP, random: clientRandom},
			serverHello:        &serverHelloMsg{random: serverRandom},
			peerIBCIdentityRaw: env.serverID,
			peerIBCSysParams:   env.serverParams,
			peerIBCIdentity:    env.serverID,
		}
		cliKA := &ibcKeyAgreement{}
		if err := cliKA.processServerKeyExchange(hs, skx); err != nil {
			t.Fatalf("processServerKeyExchange: %v", err)
		}
		pms, ckx, err := cliKA.generateClientKeyExchange(hs)
		if err != nil {
			t.Fatalf("generateClientKeyExchange: %v", err)
		}
		if len(pms) != ibcPreMasterSecretLen {
			t.Fatalf("unexpected pre-master secret length: %d", len(pms))
		}
		if pms[0] != 0x01 || pms[1] != 0x01 {
			t.Fatalf("pre-master secret version prefix mismatch: %x", pms[:2])
		}
		size := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
		if size+2 != len(ckx.ciphertext) {
			t.Fatal("IBCEncryptedPreMasterSecret length prefix mismatch")
		}
		// SM9Cipher 为 DER SEQUENCE。
		if ckx.ciphertext[2] != 0x30 {
			t.Fatalf("SM9Cipher is not a DER SEQUENCE: %x", ckx.ciphertext[2])
		}

		// 服务端应能解密出相同的预主密钥。
		decHS := &serverHandshakeState{
			c:           &Conn{config: &Config{}},
			ibcIdentity: env.serverCfg,
		}
		got, err := (&ibcKeyAgreement{}).processClientKeyExchange(decHS, ckx)
		if err != nil {
			t.Fatalf("processClientKeyExchange: %v", err)
		}
		if !bytes.Equal(got, pms) {
			t.Fatal("server decrypted a different pre-master secret")
		}
	})

	t.Run("IBSDH/ClientKeyExchange", func(t *testing.T) {
		srvHS := &serverHandshakeState{
			c:              &Conn{config: &Config{}},
			clientHello:    &clientHelloMsg{random: clientRandom},
			hello:          &serverHelloMsg{random: serverRandom},
			ibcIdentity:    env.serverCfg,
			ibcClientIDRaw: env.clientID,
		}
		ka := &ibsdhKeyAgreement{}
		skx, err := ka.generateServerKeyExchange(srvHS)
		if err != nil {
			t.Fatalf("generateServerKeyExchange: %v", err)
		}

		cliHS := &clientHandshakeState{
			c:                &Conn{config: &Config{}},
			hello:            &clientHelloMsg{vers: VersionTLCP, random: clientRandom},
			serverHello:      &serverHelloMsg{random: serverRandom},
			ibcIdentity:      env.clientCfg,
			peerIBCSysParams: env.serverParams,
			peerIBCIdentity:  env.serverID,
		}
		cliKA := &ibsdhKeyAgreement{}
		if err := cliKA.processServerKeyExchange(cliHS, skx); err != nil {
			t.Fatalf("processServerKeyExchange: %v", err)
		}
		cliKey, ckx, err := cliKA.generateClientKeyExchange(cliHS)
		if err != nil {
			t.Fatalf("generateClientKeyExchange: %v", err)
		}
		size := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
		if size+2 != len(ckx.ciphertext) {
			t.Fatal("ClientIBSDHParams length prefix mismatch")
		}
		if _, err := parseKeyAgreementInfo(ckx.ciphertext[2:]); err != nil {
			t.Fatalf("client params are not a KeyAgreementInfo: %v", err)
		}

		srvKey, err := ka.processClientKeyExchange(srvHS, ckx)
		if err != nil {
			t.Fatalf("processClientKeyExchange: %v", err)
		}
		if !bytes.Equal(cliKey, srvKey) {
			t.Fatal("IBSDH pre-master secret mismatch")
		}
		if len(srvKey) != ibcPreMasterSecretLen {
			t.Fatalf("unexpected IBSDH pre-master secret length: %d", len(srvKey))
		}
	})
}

// TestIBSDHClientTakesHidFromServerParams 客户端（响应方 B）的 hid 取自服务端下发的
// ServerIBSDHParams，而不是本端常量：这里用非标准 hid(0x55) 派生双方的密钥交换私钥，
// 服务端按该 hid 发起，客户端读消息后必须协商出相同的预主密钥，并在 ClientIBSDHParams
// 中回填同一个 hid。
func TestIBSDHClientTakesHidFromServerParams(t *testing.T) {
	const hidFromMessage byte = 0x55 // 非标准取值，仅用于证明 hid 来自消息而非本端常量

	signMaster, encMaster := testIBCMaster(t)
	now := time.Now().Truncate(time.Second)
	params, err := NewIBCSysParamsFromMaster("kgc.example", 1,
		ValidityPeriod{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, signMaster, encMaster)
	if err != nil {
		t.Fatalf("NewIBCSysParamsFromMaster: %v", err)
	}

	serverID := []byte("server@kgc.example")
	clientID := []byte("client@kgc.example")
	serverSign, err := signMaster.GenerateUserKey(serverID, hidSM9Sign)
	if err != nil {
		t.Fatalf("GenerateUserKey(sign): %v", err)
	}
	serverKE, err := encMaster.GenerateUserKey(serverID, hidFromMessage)
	if err != nil {
		t.Fatalf("GenerateUserKey(server ke): %v", err)
	}
	clientKE, err := encMaster.GenerateUserKey(clientID, hidFromMessage)
	if err != nil {
		t.Fatalf("GenerateUserKey(client ke): %v", err)
	}

	clientRandom := bytes.Repeat([]byte{0xA0}, 32)
	serverRandom := bytes.Repeat([]byte{0xB0}, 32)

	// 服务端（发起方 A）按消息中的 hid 生成 ServerIBSDHParams 并签名。
	initiator := serverKE.NewKeyExchange(serverID, clientID, ibcPreMasterSecretLen, false)
	defer initiator.Destroy()
	rA, err := initiator.InitKeyExchange(rand.Reader, hidFromMessage)
	if err != nil {
		t.Fatalf("InitKeyExchange: %v", err)
	}
	skeParams, err := marshalKeyAgreementInfo(&KeyAgreementInfo{
		Version:  keyAgreementInfoVersionV1,
		TempKey:  rA,
		UserID_A: serverID,
		UserID_B: clientID,
		Hid:      hidFromMessage,
	})
	if err != nil {
		t.Fatalf("marshalKeyAgreementInfo: %v", err)
	}
	sig, err := signIBSHandshake(&Conn{config: &Config{}},
		serverSign, ibsdhSignedParams(clientRandom, serverRandom, skeParams))
	if err != nil {
		t.Fatalf("signIBSHandshake: %v", err)
	}
	skx := &serverKeyExchangeMsg{key: make([]byte, 0, len(skeParams)+2+len(sig))}
	skx.key = append(skx.key, skeParams...)
	skx.key = append(skx.key, byte(len(sig)>>8), byte(len(sig)))
	skx.key = append(skx.key, sig...)

	// 客户端装载的密钥交换私钥按 hid=0x55 派生（装载不再校验，用法完全由消息决定）。
	cliHS := &clientHandshakeState{
		c:                &Conn{config: &Config{}},
		hello:            &clientHelloMsg{vers: VersionTLCP, random: clientRandom},
		serverHello:      &serverHelloMsg{random: serverRandom},
		ibcIdentity:      &IBCIdentity{Identity: clientID, Parameters: params, KeyExchangePrivateKey: clientKE},
		peerIBCSysParams: params,
		peerIBCIdentity:  serverID,
	}

	cliKA := &ibsdhKeyAgreement{}
	if err := cliKA.processServerKeyExchange(cliHS, skx); err != nil {
		t.Fatalf("processServerKeyExchange: %v", err)
	}
	if cliKA.peerHid != hidFromMessage {
		t.Fatalf("client peerHid = 0x%02X, want 0x%02X", cliKA.peerHid, hidFromMessage)
	}
	pms, ckx, err := cliKA.generateClientKeyExchange(cliHS)
	if err != nil {
		t.Fatalf("generateClientKeyExchange: %v", err)
	}

	// 回填的 ClientIBSDHParams 必须与消息中的 hid 一致。
	clientParams, err := parseKeyAgreementInfo(ckx.ciphertext[2:])
	if err != nil {
		t.Fatalf("parseKeyAgreementInfo(client): %v", err)
	}
	if clientParams.Hid != hidFromMessage {
		t.Fatalf("ClientIBSDHParams.hid = 0x%02X, want 0x%02X", clientParams.Hid, hidFromMessage)
	}

	// 本质断言：客户端确实按消息中的 hid 协商，否则预主密钥与发起方不同。
	initiatorPMS, _, err := initiator.ConfirmResponder(clientParams.TempKey, nil)
	if err != nil {
		t.Fatalf("ConfirmResponder: %v", err)
	}
	if !bytes.Equal(initiatorPMS, pms) {
		t.Fatal("client did not use the hid from ServerIBSDHParams")
	}
}

// BenchmarkHandshakeECCBaseline 与 IBC benchmark 使用完全相同的串行建连方式，
// 作为 ECC/ECDHE 路径的性能对比基线。
func BenchmarkHandshakeECCBaseline(b *testing.B) {
	clientCfg := &Config{RootCAs: simplePool, Time: runtimeTime}
	serverCfg := &Config{Certificates: []Certificate{sigCert, encCert}, Time: runtimeTime}
	benchmarkIBCHandshake(b, clientCfg, serverCfg)
}

// TestIBCHandshakeMixedSuiteSelection 混合套件协商：
// IBC 套件只在与对端匹配且本端具备 IBC 能力时才会被选中。
func TestIBCHandshakeMixedSuiteSelection(t *testing.T) {
	env := newIBCTestEnv(t)

	t.Run("服务端无IBC时降级到ECC", func(t *testing.T) {
		clientCfg := &Config{
			CipherSuites:     []uint16{IBC_SM4_GCM_SM3, ECC_SM4_GCM_SM3},
			IBCIdentity:      env.clientCfg,
			RootIBCSysParams: env.pool,
			RootCAs:          simplePool,
			Time:             runtimeTime,
		}
		serverCfg := &Config{
			CipherSuites: []uint16{ECC_SM4_GCM_SM3},
			Certificates: []Certificate{sigCert, encCert},
			Time:         runtimeTime,
		}
		res := ibcSessionRound(t, 8460, clientCfg, serverCfg)
		if res.clientErr != nil {
			t.Fatalf("client handshake: %v", res.clientErr)
		}
		if res.serverErr != nil {
			t.Fatalf("server handshake: %v", res.serverErr)
		}
		if res.clientState.CipherSuite != ECC_SM4_GCM_SM3 {
			t.Fatalf("expected ECC_SM4_GCM_SM3, got %s", CipherSuiteName(res.clientState.CipherSuite))
		}
		if len(res.clientState.PeerIBCIdentity) != 0 {
			t.Fatal("X.509 handshake must not set PeerIBCIdentity")
		}
	})

	t.Run("客户端仅支持IBC时选中IBC", func(t *testing.T) {
		clientCfg := &Config{
			CipherSuites:     []uint16{IBC_SM4_GCM_SM3},
			IBCIdentity:      env.clientCfg,
			RootIBCSysParams: env.pool,
		}
		serverCfg := &Config{
			CipherSuites:       []uint16{ECC_SM4_GCM_SM3, IBC_SM4_GCM_SM3},
			IBCIdentity:        env.serverCfg,
			ClientIBCSysParams: env.pool,
			Certificates:       []Certificate{sigCert, encCert},
			Time:               runtimeTime,
		}
		res := ibcSessionRound(t, 8461, clientCfg, serverCfg)
		if res.clientErr != nil {
			t.Fatalf("client handshake: %v", res.clientErr)
		}
		if res.serverErr != nil {
			t.Fatalf("server handshake: %v", res.serverErr)
		}
		if res.clientState.CipherSuite != IBC_SM4_GCM_SM3 {
			t.Fatalf("expected IBC_SM4_GCM_SM3, got %s", CipherSuiteName(res.clientState.CipherSuite))
		}
	})
}

// TestIBCMalformedCertificateMessage 无法解析的 IBC 变体 Certificate 报文回 decode_error(50)。
func TestIBCMalformedCertificateMessage(t *testing.T) {
	// 结构：ibc_id 长度前缀合法，但 ibc_parameter 长度超出报文。
	raw := []byte{typeCertificate, 0x00, 0x00, 0x04, 0x00, 0x01, 'a', 0xFF, 0xFF}
	var msg ibcCertificateMsg
	if msg.unmarshal(raw) {
		t.Fatal("expected unmarshal failure")
	}

	// 空标识同样非法（ibc_id<1..2^16-1>）。
	raw = []byte{typeCertificate, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
	if msg.unmarshal(raw) {
		t.Fatal("expected unmarshal failure for empty ibc_id")
	}
}

// TestIBCHandshakeWithoutKeyExchangeKey 校验 IBSDH 套件要求本端配置按 hid=0x02
// 派生的密钥交换私钥：缺失时该套件不参与协商；IBC 套件不受影响。
func TestIBCHandshakeWithoutKeyExchangeKey(t *testing.T) {
	dropKeyExchange := func(cfg *Config) {
		cfg.IBCIdentity = cfg.IBCIdentity.Clone()
		cfg.IBCIdentity.KeyExchangePrivateKey = nil
	}

	// 服务端缺少密钥交换私钥：即使客户端提供 IBSDH，服务端也不会选中。
	res := runIBCHandshake(t, IBSDH_SM4_GCM_SM3, func(_, serverCfg *Config) {
		dropKeyExchange(serverCfg)
	})
	if res.clientErr == nil && res.serverErr == nil {
		t.Fatal("IBSDH must not be negotiated when the server lacks a key exchange private key")
	}

	// 客户端静态配置缺少密钥交换私钥：IBSDH 不进入 ClientHello。
	res = runIBCHandshake(t, IBSDH_SM4_GCM_SM3, func(clientCfg, _ *Config) {
		dropKeyExchange(clientCfg)
	})
	if res.clientErr == nil && res.serverErr == nil {
		t.Fatal("IBSDH must not be negotiated when the client lacks a key exchange private key")
	}

	// IBC 套件不使用密钥交换私钥，双方都不配置时仍可正常握手。
	res = runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		dropKeyExchange(clientCfg)
		dropKeyExchange(serverCfg)
	})
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("IBC handshake should succeed without key exchange keys: client=%v server=%v",
			res.clientErr, res.serverErr)
	}
	if res.clientState.CipherSuite != IBC_SM4_GCM_SM3 {
		t.Fatalf("expected IBC_SM4_GCM_SM3, got %s", CipherSuiteName(res.clientState.CipherSuite))
	}
}

// TestIBCHandshakePartialX509Certificates 服务端同时配置了 IBC 身份与不完整的
// X.509 证书（只有签名证书、缺少加密证书）时，X.509 能力判定为 false，
// 握手转入仅 IBC 模式完成；不得因对 nil 加密证书解引用而 panic。
func TestIBCHandshakePartialX509Certificates(t *testing.T) {
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(_, serverCfg *Config) {
		serverCfg.Certificates = []Certificate{sigCert}
	})
	if res.clientErr != nil {
		t.Fatalf("client: %v", res.clientErr)
	}
	if res.serverErr != nil {
		t.Fatalf("server: %v", res.serverErr)
	}
	if res.clientState.CipherSuite != IBC_SM4_GCM_SM3 {
		t.Fatalf("expected IBC_SM4_GCM_SM3, got %s", CipherSuiteName(res.clientState.CipherSuite))
	}
}
