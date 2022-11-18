// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlcp

import (
	x509 "github.com/emmansun/gmsm/smx509"
	"runtime"
	"sync"
	"sync/atomic"
)

// cacheEntry 证书引用缓存项目
type cacheEntry struct {
	refs int64             // 引用计数器
	cert *x509.Certificate // 证书对象
}

// certCache 实现了一个内部X.509证书对象的引用表，它运行一个证书被多个 Conn 共享，
// 通过缓存的方式缩短同一个证书的从DER编码解析为X.509证书的时间。
//
// 证书通过缓存结构 cacheEntry 存储于表中，
// 每当通过解析同一个DER证书时，对于该缓存项中的计数器增加1。
//
// 缓存的证书被包装在 activeCert 结构中，该结构应由调用者持有，并在运行期间保存该
// 引用，在该调用者放弃该引用发生gc时，将会使得 缓存中该计数器 -1，当计数器为0时。
// 删除该证书的缓存。
//
// 该缓存从 go/crypto/tls/cache.go 同步
// 更多内容可参考BoringSSL:
// - https://boringssl.googlesource.com/boringssl/+/master/include/openssl/pool.h
// - https://boringssl.googlesource.com/boringssl/+/master/crypto/pool/pool.c
type certCache struct {
	sync.Map
}

// clientCertCache 全局的证书缓存
var clientCertCache = new(certCache)

// activeCert 用于给调用者持有引用保证不会被gc
// 当持有者放弃这个引用时则减少引用计数器
type activeCert struct {
	cert *x509.Certificate
}

// active 该方法将会增加缓存中引用计数器的数目，然后设置在该引用被被回收时的回调，用于减少计数器
// 当计数器为0时，清理缓存。
func (cc *certCache) active(e *cacheEntry) *activeCert {
	atomic.AddInt64(&e.refs, 1)
	a := &activeCert{e.cert}
	runtime.SetFinalizer(a, func(_ *activeCert) {
		if atomic.AddInt64(&e.refs, -1) == 0 {
			cc.evict(e)
		}
	})
	return a
}

// evict 从缓存中删除 cacheEntry
func (cc *certCache) evict(e *cacheEntry) {
	cc.Delete(string(e.cert.Raw))
}

// newCert 解析DER返回 activeCert 证书对象。
//
// 如果该DER已经被缓存，则返回被缓存的 activeCert，否则建立该DER的证书对象缓存。
//
// 注意：调用者应在运行期间妥善保持住返回 *activeCert 引用，否则无法实现缓存效果。
func (cc *certCache) newCert(der []byte) (*activeCert, error) {
	if entry, ok := cc.Load(string(der)); ok {
		return cc.active(entry.(*cacheEntry)), nil
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	entry := &cacheEntry{cert: cert}
	if entry, loaded := cc.LoadOrStore(string(der), entry); loaded {
		return cc.active(entry.(*cacheEntry)), nil
	}
	return cc.active(entry), nil
}
