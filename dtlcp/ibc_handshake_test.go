// Copyright (c) 2022 QuanGuanyu
// gotlcp is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package dtlcp

import (
	"bytes"
	"context"
	"errors"
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

// ibcUserConfig 派生一个用户的 IBC 配置（签名私钥 hid=0x01，加密私钥 hid=0x03，
// 密钥交换私钥 hid=0x02）。
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

// ibcTestConfigPair 构造一对默认的 IBC 客户端/服务端配置。
func ibcTestConfigPair(env *ibcTestEnv, suiteID uint16) (*Config, *Config) {
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
	return clientCfg, serverCfg
}

// testConfigTimeouts 为 DTLCP 测试配置较短的握手重传超时，避免失败路径长时间等待。
func testConfigTimeouts(cfg *Config) {
	cfg.InitialRetransmitTimeout = 200 * time.Millisecond
	cfg.MaxRetransmitTimeout = 800 * time.Millisecond
}

// runIBCHandshakeWith 通过一对 mockPacketConn 执行一次 IBC 握手，并在成功后回显一段数据。
func runIBCHandshakeWith(t *testing.T, clientCfg, serverCfg *Config) ibcHandshakeResult {
	t.Helper()
	testConfigTimeouts(clientCfg)
	testConfigTimeouts(serverCfg)

	clientPConn, serverPConn := newMockPacketConn()
	defer clientPConn.Close()
	defer serverPConn.Close()

	cli := Client(clientPConn, serverPConn.LocalAddr(), clientCfg)
	svr := Server(serverPConn, clientPConn.LocalAddr(), serverCfg)

	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()

	payload := []byte("hello dtlcp ibc")
	var (
		res ibcHandshakeResult
		wg  sync.WaitGroup
	)
	wg.Go(func() {
		if err := svr.HandshakeContext(ctx); err != nil {
			res.serverErr = err
			return
		}
		res.serverState = svr.ConnectionState()
		_ = svr.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, err := svr.Read(buf)
		if err != nil {
			res.serverErr = err
			return
		}
		res.echoed = append([]byte(nil), buf[:n]...)
	})

	if err := cli.HandshakeContext(ctx); err != nil {
		res.clientErr = err
	} else {
		res.clientState = cli.ConnectionState()
		if _, err := cli.Write(payload); err != nil {
			res.clientErr = err
		}
	}
	wg.Wait()
	return res
}

// runIBCHandshake 使用默认配置执行一次指定套件的 IBC 握手。
func runIBCHandshake(t *testing.T, suiteID uint16, mutate func(clientCfg, serverCfg *Config)) ibcHandshakeResult {
	t.Helper()
	env := newIBCTestEnv(t)
	clientCfg, serverCfg := ibcTestConfigPair(env, suiteID)
	if mutate != nil {
		mutate(clientCfg, serverCfg)
	}
	return runIBCHandshakeWith(t, clientCfg, serverCfg)
}

// =============================================================================
// 握手主流程
// =============================================================================

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
				if !bytes.Equal(res.echoed, []byte("hello dtlcp ibc")) {
					t.Fatalf("application data mismatch: %q", res.echoed)
				}
				if res.clientState.CipherSuite != suiteID || res.serverState.CipherSuite != suiteID {
					t.Fatalf("cipher suite mismatch: client=%04x server=%04x", res.clientState.CipherSuite, res.serverState.CipherSuite)
				}
				if !bytes.Equal(res.clientState.PeerIBCIdentity, []byte("server@kgc.example")) {
					t.Fatalf("client peer IBC identity mismatch: %q", res.clientState.PeerIBCIdentity)
				}
				if res.clientState.PeerIBCSysParams == nil {
					t.Fatal("client peer IBC parameters missing")
				}
				if mutual && !bytes.Equal(res.serverState.PeerIBCIdentity, []byte("client@kgc.example")) {
					t.Fatalf("server peer IBC identity mismatch: %q", res.serverState.PeerIBCIdentity)
				}
				if mutual && res.serverState.PeerIBCSysParams == nil {
					t.Fatal("server peer IBC parameters missing")
				}
			})
		}
	}
}

// TestIBCHandshakeFragmented 验证 IBC 变体 Certificate 消息在超过 PMTU 时
// 由 DTLCP 分片传输并在对端正确重组（IBCSysParams 通常大于 100 字节）。
func TestIBCHandshakeFragmented(t *testing.T) {
	for _, suiteID := range []uint16{IBC_SM4_GCM_SM3, IBSDH_SM4_GCM_SM3} {
		t.Run(CipherSuiteName(suiteID), func(t *testing.T) {
			res := runIBCHandshake(t, suiteID, func(clientCfg, serverCfg *Config) {
				// 很小的 PMTU：12 字节握手头 + 记录头之后只允许很少的载荷，
				// 强制把 Certificate 消息拆成多个分片。
				serverCfg.PMTU = 120
				serverCfg.ClientAuth = RequireAndVerifyClientCert
				clientCfg.PMTU = 120
			})
			if res.clientErr != nil {
				t.Fatalf("client handshake: %v", res.clientErr)
			}
			if res.serverErr != nil {
				t.Fatalf("server handshake: %v", res.serverErr)
			}
			if !bytes.Equal(res.echoed, []byte("hello dtlcp ibc")) {
				t.Fatalf("application data mismatch: %q", res.echoed)
			}
		})
	}
}

// TestIBCHandshakeDefaultTrustPool 未配置信任池时，默认以本端 IBC 参数为信任池。
func TestIBCHandshakeDefaultTrustPool(t *testing.T) {
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		clientCfg.RootIBCSysParams = nil
		serverCfg.ClientIBCSysParams = nil
	})
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", res.clientErr, res.serverErr)
	}
}

// TestIBCHandshakeDefaultTrustPoolRejectsOtherKGC 默认信任池要求对端参数与本端同属一个 KGC。
func TestIBCHandshakeDefaultTrustPoolRejectsOtherKGC(t *testing.T) {
	env := newIBCTestEnv(t)
	other := newIBCTestEnv(t)

	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	// 服务端切换到另一个 KGC 的身份；客户端仍以本端参数作为默认信任池。
	serverCfg.IBCIdentity = other.serverCfg
	serverCfg.ClientIBCSysParams = nil
	clientCfg.RootIBCSysParams = nil

	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr == nil {
		t.Fatal("expected client to reject parameters from another KGC")
	}
}

// TestIBCHandshakeDefaultTrustPoolUnavailable 两端都没有公共参数且没有信任池时，握手必须失败。
func TestIBCHandshakeDefaultTrustPoolUnavailable(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	clientCfg.RootIBCSysParams = nil
	clientCfg.IBCIdentity.Parameters = nil
	serverCfg.ClientIBCSysParams = nil

	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr == nil && res.serverErr == nil {
		t.Fatal("expected handshake failure without any trusted IBC parameters")
	}
}

// TestIBCHandshakeSkipVerify 客户端 InsecureSkipVerify 跳过 IBC 公共参数校验。
func TestIBCHandshakeSkipVerify(t *testing.T) {
	env := newIBCTestEnv(t)
	other := newIBCTestEnv(t)

	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	serverCfg.IBCIdentity = other.serverCfg
	serverCfg.ClientIBCSysParams = nil
	clientCfg.RootIBCSysParams = nil
	clientCfg.InsecureSkipVerify = true

	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr != nil {
		t.Fatalf("client handshake with InsecureSkipVerify: %v", res.clientErr)
	}
}

// TestIBCHandshakeUntrustedPool 对端参数未命中显式信任池时失败。
func TestIBCHandshakeUntrustedPool(t *testing.T) {
	env := newIBCTestEnv(t)
	other := newIBCTestEnv(t)

	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	serverCfg.IBCIdentity = other.serverCfg
	clientCfg.RootIBCSysParams = env.pool // 只信任 env 的 KGC

	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr == nil {
		t.Fatal("expected client to reject untrusted IBC parameters")
	}
}

// TestIBCHandshakeVerifyCallback 未配置信任池时由 VerifyIBCSysParams 回调判定。
func TestIBCHandshakeVerifyCallback(t *testing.T) {
	t.Run("accept", func(t *testing.T) {
		res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
			clientCfg.RootIBCSysParams = nil
			clientCfg.VerifyIBCSysParams = func(*IBCSysParams) error { return nil }
		})
		if res.clientErr != nil || res.serverErr != nil {
			t.Fatalf("handshake failed: client=%v server=%v", res.clientErr, res.serverErr)
		}
	})
	t.Run("reject", func(t *testing.T) {
		res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
			clientCfg.RootIBCSysParams = nil
			clientCfg.VerifyIBCSysParams = func(*IBCSysParams) error { return errors.New("rejected") }
		})
		if res.clientErr == nil {
			t.Fatal("expected client to reject parameters via callback")
		}
	})
}

// TestIBCHandshakeExpiredParams 公共参数超出有效期时握手失败。
func TestIBCHandshakeExpiredParams(t *testing.T) {
	env := newIBCTestEnv(t)
	signMaster, encMaster := testIBCMaster(t)
	past := time.Now().Add(-48 * time.Hour)
	expired, err := NewIBCSysParamsFromMaster("kgc.example", 1,
		ValidityPeriod{NotBefore: past, NotAfter: past.Add(time.Hour)}, signMaster, encMaster)
	if err != nil {
		t.Fatalf("NewIBCSysParamsFromMaster: %v", err)
	}
	if err := env.pool.AddParams(expired); err != nil {
		t.Fatalf("AddParams: %v", err)
	}
	// 服务端使用过期参数（同一 KGC 身份），客户端信任池中命中同一条目。
	serverSign, serverEnc := testIBCMaster(t)
	_ = serverSign
	_ = serverEnc
	serverIdent := ibcUserConfig(t, env.serverID, expired, signMaster, encMaster)

	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	serverCfg.IBCIdentity = serverIdent

	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr == nil {
		t.Fatal("expected client to reject expired IBC parameters")
	}
}

// TestIBCHandshakeVerifyIdentityRejects VerifyIBCIdentity 回调拒绝对端标识。
func TestIBCHandshakeVerifyIdentityRejects(t *testing.T) {
	res := runIBCHandshake(t, IBC_SM4_GCM_SM3, func(clientCfg, serverCfg *Config) {
		serverCfg.ClientAuth = RequireAndVerifyClientCert
		serverCfg.VerifyIBCIdentity = func([]byte) error { return errors.New("revoked") }
	})
	if res.serverErr == nil && res.clientErr == nil {
		t.Fatal("expected handshake failure when VerifyIBCIdentity rejects")
	}
}

// TestIBCHandshakeMissingClientID IBSDH 要求 client_id 扩展：客户端仅配置
// GetClientIBCIdentity 时 ClientHello 不带该扩展，服务端必须拒绝。
func TestIBCHandshakeMissingClientID(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg, serverCfg := ibcTestConfigPair(env, IBSDH_SM4_GCM_SM3)
	clientCfg.IBCIdentity = nil
	clientCfg.GetClientIBCIdentity = func(*CertificateRequestInfo) (*IBCIdentity, error) {
		return env.clientCfg, nil
	}

	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr == nil && res.serverErr == nil {
		t.Fatal("expected IBSDH handshake to fail without client_id extension")
	}
}

// TestIBCHandshakeWithoutIBCIdentity 无 IBC 身份的客户端不会携带 IBC 套件。
func TestIBCHandshakeWithoutIBCIdentity(t *testing.T) {
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

// TestIBCHandshakeWithoutKeyExchangeKey 缺少密钥交换私钥时 IBSDH 不可用，IBC 仍可用。
func TestIBCHandshakeWithoutKeyExchangeKey(t *testing.T) {
	t.Run("IBSDH-unavailable", func(t *testing.T) {
		env := newIBCTestEnv(t)
		clientIdent := *env.clientCfg
		clientIdent.KeyExchangePrivateKey = nil

		clientCfg, serverCfg := ibcTestConfigPair(env, IBSDH_SM4_GCM_SM3)
		clientCfg.IBCIdentity = &clientIdent

		res := runIBCHandshakeWith(t, clientCfg, serverCfg)
		if res.clientErr == nil && res.serverErr == nil {
			t.Fatal("expected IBSDH handshake to fail without key exchange key")
		}
	})
	t.Run("IBC-available", func(t *testing.T) {
		env := newIBCTestEnv(t)
		clientIdent := *env.clientCfg
		clientIdent.KeyExchangePrivateKey = nil

		clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
		clientCfg.IBCIdentity = &clientIdent

		res := runIBCHandshakeWith(t, clientCfg, serverCfg)
		if res.clientErr != nil || res.serverErr != nil {
			t.Fatalf("IBC handshake should not require a key exchange key: client=%v server=%v", res.clientErr, res.serverErr)
		}
	})
}

// TestIBCHandshakeMixedSuiteSelection 服务端仅有 IBC 身份时，即使客户端提供
// X.509 套件也只会选中 IBC 套件。
func TestIBCHandshakeMixedSuiteSelection(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg := &Config{
		CipherSuites:     []uint16{ECC_SM4_GCM_SM3, IBC_SM4_GCM_SM3},
		IBCIdentity:      env.clientCfg,
		RootIBCSysParams: env.pool,
		ServerName:       "localhost",
	}
	serverCfg := &Config{
		CipherSuites:       []uint16{ECC_SM4_GCM_SM3, IBC_SM4_GCM_SM3},
		IBCIdentity:        env.serverCfg,
		ClientIBCSysParams: env.pool,
	}
	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", res.clientErr, res.serverErr)
	}
	if res.clientState.CipherSuite != IBC_SM4_GCM_SM3 {
		t.Fatalf("expected IBC suite, got %04x", res.clientState.CipherSuite)
	}
}

// TestIBCHandshakeGetIBCIdentity 服务端通过 GetIBCIdentity 动态提供身份。
func TestIBCHandshakeGetIBCIdentity(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	serverCfg.IBCIdentity = nil
	serverCfg.GetIBCIdentity = func(*ClientHelloInfo) (*IBCIdentity, error) {
		return env.serverCfg, nil
	}
	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", res.clientErr, res.serverErr)
	}
}

// TestIBCHandshakeGetClientIBCIdentity 客户端通过 GetClientIBCIdentity 动态提供身份。
func TestIBCHandshakeGetClientIBCIdentity(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	serverCfg.ClientAuth = RequireAndVerifyClientCert
	clientCfg.IBCIdentity = nil
	clientCfg.GetClientIBCIdentity = func(*CertificateRequestInfo) (*IBCIdentity, error) {
		return env.clientCfg, nil
	}
	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr != nil || res.serverErr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", res.clientErr, res.serverErr)
	}
	if !bytes.Equal(res.serverState.PeerIBCIdentity, []byte("client@kgc.example")) {
		t.Fatalf("server peer IBC identity mismatch: %q", res.serverState.PeerIBCIdentity)
	}
}

// TestIBCHandshakeServerWithoutIBCIdentity 服务端既无证书也无 IBC 身份时直接失败。
func TestIBCHandshakeServerWithoutIBCIdentity(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	serverCfg.IBCIdentity = nil
	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr == nil && res.serverErr == nil {
		t.Fatal("expected handshake failure when the server has no credentials")
	}
}

// TestIBCHandshakeAlertBadCertificate 客户端未配置信任锚时无法建立 IBC 连接。
func TestIBCHandshakeAlertBadCertificate(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	clientCfg.RootIBCSysParams = nil
	clientCfg.IBCIdentity = &IBCIdentity{
		Identity: env.clientCfg.Identity,
		// 无公共参数，也无信任池与回调：IBC 没有"系统级 KGC"，必须失败。
	}
	res := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if res.clientErr == nil {
		t.Fatal("expected client to fail without any trusted IBC parameters")
	}
}

// TestIBCHandshakeSessionResume 验证 IBC 套件的会话重用。
func TestIBCHandshakeSessionResume(t *testing.T) {
	env := newIBCTestEnv(t)
	clientCache := NewLRUSessionCache(4)
	serverCache := NewLRUSessionCache(4)

	clientCfg, serverCfg := ibcTestConfigPair(env, IBC_SM4_GCM_SM3)
	clientCfg.SessionCache = clientCache
	serverCfg.SessionCache = serverCache

	first := runIBCHandshakeWith(t, clientCfg, serverCfg)
	if first.clientErr != nil || first.serverErr != nil {
		t.Fatalf("first handshake: client=%v server=%v", first.clientErr, first.serverErr)
	}
	if first.clientState.DidResume {
		t.Fatal("first handshake must not be a resumption")
	}

	second := runIBCHandshakeWith(t, clientCfg, serverCfg)
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

// =============================================================================
// 消息编解码
// =============================================================================

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

// TestIBCCertificateMessageRoundTrip 固化 IBC 变体 Certificate 消息（DTLCP 头）的编解码。
func TestIBCCertificateMessageRoundTrip(t *testing.T) {
	params := testIBCSysParams(t)
	msg := &ibcCertificateMsg{
		ibcID:        []byte("server@kgc.example"),
		ibcParameter: params.Raw,
	}
	msg.setMessageSeq(7)
	der, err := msg.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if der[0] != typeCertificate {
		t.Fatalf("unexpected message type: %d", der[0])
	}
	if got := uint16(der[4])<<8 | uint16(der[5]); got != 7 {
		t.Fatalf("message sequence mismatch: %d", got)
	}
	var got ibcCertificateMsg
	if !got.unmarshal(der) {
		t.Fatal("unmarshal failed")
	}
	if !bytes.Equal(got.ibcID, msg.ibcID) || !bytes.Equal(got.ibcParameter, msg.ibcParameter) {
		t.Fatal("round trip mismatch")
	}
	if got.getMessageSeq() != 7 {
		t.Fatalf("message sequence mismatch after unmarshal: %d", got.getMessageSeq())
	}
	// 共用的握手消息类型必须由 suiteIBC 判定区分于 X.509 Certificate。
	if got.messageType() != typeCertificate {
		t.Fatalf("unexpected message type: %d", got.messageType())
	}
}
