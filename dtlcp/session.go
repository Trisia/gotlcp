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
	"container/list"
	x509 "github.com/emmansun/gmsm/smx509"
	"sync"
	"time"
)

// SessionState 包含了 TLCP 会话重用的密码参数。
// 由握手完成后产生，可用于后续会话重用握手中快速恢复连接。
type SessionState struct {
	sessionId        []byte              // 会话ID
	vers             uint16              // TLCP 版本号
	cipherSuite      uint16              // 握手使用的密码套件ID
	masterSecret     []byte              // 握手协议协商得到的主密钥
	peerCertificates []*x509.Certificate // 对端证书
	createdAt        time.Time           // Session创建时间
}

// SessionCache 会话缓存器接口，用于存储和检索会话状态。
// 实现必须支持多 goroutine 并发访问。
//
// Get 根据 sessionKey 查找会话，若 sessionKey 为空则返回最近一个会话。
// Put 存储会话，若 cs 为 nil 则删除该会话。
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

// NewLRUSessionCache 创建指定容量的 LRU 会话缓存器。
// 参数 capacity 为最大缓存条目数。若 capacity < 1，使用默认值 64。
// 当缓存满时，优先淘汰最近最少使用的条目，并置零对应的主密钥。
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
	oldCs := entry.state
	if oldCs != nil {
		// 清理旧的主密钥
		setZero(oldCs.masterSecret)
		oldCs.masterSecret = nil
	}
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
