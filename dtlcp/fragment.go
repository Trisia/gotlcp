// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import "time"

// fragmentBuffer 握手消息分片重组缓冲区
// 用于缓存和重组跨多个 UDP 报文的分片握手消息
type fragmentBuffer struct {
	totalLen   uint24    // 原始消息总长度（来自 handshake.length 字段）
	data       []byte    // 重组缓冲区
	received   []byte    // 位掩码：received[i>>3] 的第 (i&7) 位 = 字节索引 i 已收到
	numBytes   int       // totalLen 的 int 副本，避免重复转换
	receivedAt time.Time // 最后收到分片的时间
}

// newFragmentBuffer 创建分片重组缓冲区
// totalLen: 原始消息总长度
func newFragmentBuffer(totalLen uint24) *fragmentBuffer {
	n := int(totalLen)
	if n < 1 {
		n = 1
	}
	return &fragmentBuffer{
		totalLen: totalLen,
		data:     make([]byte, n),
		received: make([]byte, (n+7)>>3), // ceil(n/8) 字节的位掩码
		numBytes: n,
	}
}

// addFragment 添加一个分片到缓冲区
// offset: 分片在原始消息中的偏移
// length: 分片数据长度
// frag: 分片数据
// 返回 false 表示偏移/长度超出范围
func (fb *fragmentBuffer) addFragment(offset, length uint24, frag []byte) bool {
	if int(offset)+int(length) > fb.numBytes {
		return false
	}
	copy(fb.data[offset:offset+length], frag)

	// 逐字节设置位掩码中对应的位
	end := int(offset) + int(length)
	for i := int(offset); i < end; i++ {
		fb.received[i>>3] |= 1 << (i & 7)
	}
	fb.receivedAt = time.Now()
	return true
}

// complete 检查是否已收齐所有分片
func (fb *fragmentBuffer) complete() bool {
	// 检查完整字节是否全为 0xFF
	full := fb.numBytes >> 3
	for i := 0; i < full; i++ {
		if fb.received[i] != 0xFF {
			return false
		}
	}
	// 检查尾部不足 1 字节的位
	rem := fb.numBytes & 7
	if rem > 0 {
		mask := byte((1 << rem) - 1)
		if fb.received[full]&mask != mask {
			return false
		}
	}
	return true
}

// assembled 返回重组后的完整消息
// 仅在 complete() 返回 true 时调用
func (fb *fragmentBuffer) assembled() []byte {
	return fb.data
}
