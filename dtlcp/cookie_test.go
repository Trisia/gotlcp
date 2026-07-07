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
