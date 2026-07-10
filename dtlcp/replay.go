// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

// replayWindow DTLCP 重放保护滑动窗口
// 基于 DTLS RFC 6347 Section 4.1.2.6
type replayWindow struct {
	right  uint48 // 窗口右边缘（已接受的最大序列号）
	size   int    // 窗口大小（定义见 common.go defaultReplayWindowSize，最小32）
	bitmap uint64 // 位图，bit i 标记 seq (right - i) 是否已收到
}

// newReplayWindow 创建滑动窗口
// size 最小为 32
func newReplayWindow(size int) *replayWindow {
	if size < 32 {
		size = 32
	}
	return &replayWindow{size: size}
}

// check 检查序列号是否应接受
// 返回 true 表示接受（新序列号，非重放）
func (w *replayWindow) check(seq uint48) bool {
	// 情况1：序列号大于右边缘 → 窗口右移
	if seq > w.right {
		diff := seq - w.right
		if diff >= uint48(w.size) {
			// 跳跃超过窗口大小 → 清空位图
			w.bitmap = 0
		} else {
			// 滑动窗口
			w.bitmap <<= diff
		}
		w.bitmap |= 1 // 标记当前 seq
		w.right = seq
		return true
	}

	// 情况2：序列号在窗口左侧 → 拒绝
	diff := w.right - seq
	if diff >= uint48(w.size) {
		return false
	}

	// 情况3：序列号在窗口内 → 检查是否重复
	bit := uint64(1) << diff
	if w.bitmap&bit != 0 {
		return false // 重复
	}
	w.bitmap |= bit
	return true
}
