// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"crypto/hmac"
	"crypto/subtle"

	"github.com/emmansun/gmsm/sm3"
)

// generateCookie 生成无状态 DTLCP Cookie
// 使用 HMAC-SM3(secret, clientAddr || clientParams)
func generateCookie(secret []byte, clientAddr string, clientParams []byte) []byte {
	h := hmac.New(sm3.New, secret)
	h.Write([]byte(clientAddr))
	h.Write(clientParams)
	return h.Sum(nil)
}

// verifyCookie 验证 Cookie 是否合法（常数时间比较）
func verifyCookie(secret []byte, clientAddr string, clientParams, cookie []byte) bool {
	expected := generateCookie(secret, clientAddr, clientParams)
	return subtle.ConstantTimeCompare(expected, cookie) == 1
}
