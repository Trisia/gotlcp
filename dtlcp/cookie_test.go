// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"testing"
)

// TestGenerateCookie 测试 Cookie 生成：
// - 输出长度为 32 字节（SM3 输出）
// - 确定性：相同输入产生相同输出
func TestGenerateCookie(t *testing.T) {
	secret := []byte("test-secret-1234567890")
	addr := "127.0.0.1:12345"
	params := []byte{0x01, 0x02, 0x03}

	cookie := generateCookie(secret, addr, params)
	if len(cookie) != 32 {
		t.Fatalf("预期 32 字节，实际 %d 字节", len(cookie))
	}

	// 确定性：同样输入应产生同样输出
	cookie2 := generateCookie(secret, addr, params)
	if !bytes.Equal(cookie, cookie2) {
		t.Fatal("Cookie 不具确定性：相同输入产生不同输出")
	}
}

// TestVerifyCookie 测试合法 Cookie 验证通过。
func TestVerifyCookie(t *testing.T) {
	secret := []byte("test-secret-1234567890")
	addr := "127.0.0.1:12345"
	params := []byte{0x01, 0x02, 0x03}

	cookie := generateCookie(secret, addr, params)
	if !verifyCookie(secret, addr, params, cookie) {
		t.Fatal("合法 Cookie 验证失败")
	}
}

// TestVerifyCookieRejectWrongSecret 测试错误密钥导致验证失败。
func TestVerifyCookieRejectWrongSecret(t *testing.T) {
	secret := []byte("test-secret-1234567890")
	wrongSecret := []byte("wrong-secret-0987654321")
	addr := "127.0.0.1:12345"
	params := []byte{0x01, 0x02, 0x03}

	cookie := generateCookie(secret, addr, params)
	if verifyCookie(wrongSecret, addr, params, cookie) {
		t.Fatal("错误密钥应导致验证失败")
	}
}

// TestVerifyCookieRejectWrongAddr 测试错误地址导致验证失败。
func TestVerifyCookieRejectWrongAddr(t *testing.T) {
	secret := []byte("test-secret-1234567890")
	addr := "127.0.0.1:12345"
	wrongAddr := "192.168.1.1:54321"
	params := []byte{0x01, 0x02, 0x03}

	cookie := generateCookie(secret, addr, params)
	if verifyCookie(secret, wrongAddr, params, cookie) {
		t.Fatal("错误地址应导致验证失败")
	}
}

// TestVerifyCookieRejectWrongParams 测试错误参数导致验证失败。
func TestVerifyCookieRejectWrongParams(t *testing.T) {
	secret := []byte("test-secret-1234567890")
	addr := "127.0.0.1:12345"
	params := []byte{0x01, 0x02, 0x03}
	wrongParams := []byte{0x04, 0x05, 0x06}

	cookie := generateCookie(secret, addr, params)
	if verifyCookie(secret, addr, wrongParams, cookie) {
		t.Fatal("错误参数应导致验证失败")
	}
}

// TestCookieDefaultSecretUnique 验证未配置 CookieSecret 时每次生成不同的随机密钥。
func TestCookieDefaultSecretUnique(t *testing.T) {
	config := &Config{}
	srv1 := Server(nil, nil, config)
	secret1 := srv1.effectiveCookieSecret()
	if len(secret1) != 32 {
		t.Fatalf("随机密钥长度应为 32，实际 %d", len(secret1))
	}

	srv2 := Server(nil, nil, config)
	secret2 := srv2.effectiveCookieSecret()
	if bytes.Equal(secret1, secret2) {
		t.Fatal("不同连接应使用不同的随机 Cookie 密钥")
	}
}

// TestCookieDefaultSecretSameConn 验证同一连接多次调用返回相同密钥。
func TestCookieDefaultSecretSameConn(t *testing.T) {
	srv := Server(nil, nil, &Config{})
	s1 := srv.effectiveCookieSecret()
	s2 := srv.effectiveCookieSecret()
	if !bytes.Equal(s1, s2) {
		t.Fatal("同一连接的 Cookie 密钥不应改变")
	}
}

// TestCookieCustomSecret 验证配置了 CookieSecret 时使用配置值。
func TestCookieCustomSecret(t *testing.T) {
	custom := []byte("my-custom-cookie-secret-key!!")
	srv := Server(nil, nil, &Config{CookieSecret: custom})
	secret := srv.effectiveCookieSecret()
	if !bytes.Equal(secret, custom) {
		t.Fatal("应返回配置的 CookieSecret 而非随机值")
	}
}

// TestCookieDefaultNotHardcoded 验证不再使用硬编码默认密钥。
func TestCookieDefaultNotHardcoded(t *testing.T) {
	srv := Server(nil, nil, &Config{})
	secret := srv.effectiveCookieSecret()
	hardcoded := []byte("dtlcp-default-secret")
	if bytes.Equal(secret, hardcoded) {
		t.Fatal("不应再使用硬编码默认密钥 'dtlcp-default-secret'")
	}
}
