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
	"container/list"
	x509 "github.com/emmansun/gmsm/smx509"
	"sync"
	"time"
)

// SessionState 包含了TLCP会话相关的密码参数，用于会话重用
type SessionState struct {
	sessionId        []byte              // 会话ID
	vers             uint16              // TLCP 版本号
	cipherSuite      uint16              // 握手使用的密码套件ID
	masterSecret     []byte              // 握手协议协商得到的主密钥
	peerCertificates []*x509.Certificate // 对端证书
	createdAt        time.Time           // Session创建时间
}

// SessionCache 会话缓存器，用于缓存TLCP连接建立后的会话信息 SessionState
// 用于在 TLCP 协议的握手重用过程中提供会话相关的信息。
//
// 会话缓存器的实现应该考虑到多 goroutines 并发访问的问题。
type SessionCache interface {

	// Get 缓存中 sessionKey 的 SessionState，若不存在则 返回 ok  false
	//
	// 特殊的若 sessionKey 为 "" 空串时，返回最近一个会话
	Get(sessionKey string) (session *SessionState, ok bool)

	// Put 添加一个会话对象到缓存中
	Put(sessionKey string, cs *SessionState)
}

// 采用最近最少策略实现的会话缓存器
type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

// lruSessionCacheEntry 最少使用缓存项
type lruSessionCacheEntry struct {
	sessionKey string
	state      *SessionState
}

// NewLRUSessionCache 返回一个指定容量的 最近最少使用缓存（LRU）对象。
// 在缓存空间不足时，优先淘汰最近最少使用的缓存部分。
//
// 当 capacity 小于1时，使用默认容量 64
func NewLRUSessionCache(capacity int) SessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

// Put 添加一个会话对象到缓存中，若 cs 对象为空，则删除缓存中 sessionKey 对应的值。
func (c *lruSessionCache) Put(sessionKey string, cs *SessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		if cs == nil {
			c.q.Remove(elem)
			delete(c.m, sessionKey)
		} else {
			entry := elem.Value.(*lruSessionCacheEntry)
			entry.state = cs
			c.q.MoveToFront(elem)
		}
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

// Get 返回 sessionKey 关联的会话信息，若没有找到 sessionKey 对应的值，则返回 (nil, false)
func (c *lruSessionCache) Get(sessionKey string) (*SessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if sessionKey == "" {
		elem := c.q.Front()
		if elem == nil {
			return nil, false
		}
		return elem.Value.(*lruSessionCacheEntry).state, true
	}

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}
