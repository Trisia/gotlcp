// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import "time"

// fragmentBuffer 握手消息分片重组缓冲区
// 用于缓存和重组跨多个 UDP 报文的分片握手消息
type fragmentBuffer struct {
	totalLen   uint24    // 原始消息总长度（来自 handshake.length 字段）
	data       []byte    // 重组缓冲区
	received   []bool    // 各分片块是否已收到
	receivedAt time.Time // 最后收到分片的时间
}

// newFragmentBuffer 创建分片重组缓冲区
// totalLen: 原始消息总长度
// fragSize: 每片估算大小（用于位图粒度）
func newFragmentBuffer(totalLen uint24, fragSize int) *fragmentBuffer {
	numFrags := (int(totalLen) + fragSize - 1) / fragSize
	if numFrags < 1 {
		numFrags = 1
	}
	return &fragmentBuffer{
		totalLen: totalLen,
		data:     make([]byte, totalLen),
		received: make([]bool, numFrags),
	}
}

// addFragment 添加一个分片到缓冲区
// offset: 分片在原始消息中的偏移
// length: 分片数据长度
// frag: 分片数据
// 返回 false 表示偏移/长度超出范围
func (fb *fragmentBuffer) addFragment(offset, length uint24, frag []byte) bool {
	if int(offset)+int(length) > int(fb.totalLen) {
		return false
	}
	copy(fb.data[offset:offset+length], frag)

	// 标记覆盖到的分片块为已收到
	fragSize := len(fb.data) / len(fb.received)
	if fragSize == 0 {
		fragSize = 1
	}
	startIdx := int(offset) / fragSize
	endIdx := (int(offset) + int(length) - 1) / fragSize
	if endIdx >= len(fb.received) {
		endIdx = len(fb.received) - 1
	}
	for i := startIdx; i <= endIdx; i++ {
		fb.received[i] = true
	}
	fb.receivedAt = time.Now()
	return true
}

// complete 检查是否已收齐所有分片
func (fb *fragmentBuffer) complete() bool {
	for _, r := range fb.received {
		if !r {
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
