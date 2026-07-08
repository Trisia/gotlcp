// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"testing"
	"time"
)

// TestFragmentReassembly 测试分片正常收齐后可以正确重组。
func TestFragmentReassembly(t *testing.T) {
	// 构建 3000 字节的原始数据
	data := make([]byte, 3000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fb := newFragmentBuffer(3000)

	// 分 3 片：1400 + 1400 + 200
	fb.addFragment(0, 1400, data[0:1400])
	fb.addFragment(1400, 1400, data[1400:2800])
	fb.addFragment(2800, 200, data[2800:3000])

	if !fb.complete() {
		t.Fatal("所有分片已添加，complete() 应返回 true")
	}

	if !bytes.Equal(fb.assembled(), data) {
		t.Fatal("重组后的数据与原始数据不一致")
	}
}

// TestFragmentOutOfOrder 测试分片乱序到达后仍可正确重组。
func TestFragmentOutOfOrder(t *testing.T) {
	// 构建 2800 字节的原始数据
	data := make([]byte, 2800)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fb := newFragmentBuffer(2800)

	// 乱序添加：先加第2片（1400-2800），再加第1片（0-1400）
	fb.addFragment(1400, 1400, data[1400:2800])
	if fb.complete() {
		t.Fatal("仅添加第2片时 complete() 应返回 false")
	}

	fb.addFragment(0, 1400, data[0:1400])
	if !fb.complete() {
		t.Fatal("所有分片已添加，complete() 应返回 true")
	}

	if !bytes.Equal(fb.assembled(), data) {
		t.Fatal("乱序重组后的数据与原始数据不一致")
	}
}

// TestFragmentOverlapping 测试重叠分片（模拟 PMTU 变小导致重分片）正确覆盖。
func TestFragmentOverlapping(t *testing.T) {
	data := make([]byte, 2000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fb := newFragmentBuffer(2000)

	// 先以 1000 为单位添加两个分片
	fb.addFragment(0, 1000, data[0:1000])
	fb.addFragment(1000, 1000, data[1000:2000])
	if !fb.complete() {
		t.Fatal("两个分片添加后应 complete")
	}
	if !bytes.Equal(fb.assembled(), data) {
		t.Fatal("重组后的数据不一致")
	}

	// PMTU 变小导致重分片为 4 个 500 字节分片，与已接收数据重叠
	fb.addFragment(0, 500, data[0:500])
	fb.addFragment(500, 500, data[500:1000])
	fb.addFragment(1000, 500, data[1000:1500])
	fb.addFragment(1500, 500, data[1500:2000])

	if !fb.complete() {
		t.Fatal("重叠分片添加后仍应 complete")
	}
	if !bytes.Equal(fb.assembled(), data) {
		t.Fatal("重叠分片重组后的数据应与原始数据一致")
	}

	// 跨边界重叠：单个大分片覆盖之前多个小分片的边界
	fb.addFragment(100, 800, data[100:900])

	if !fb.complete() {
		t.Fatal("跨边界重叠后仍应 complete")
	}
	if !bytes.Equal(fb.assembled(), data) {
		t.Fatal("跨边界重叠重组后的数据应与原始数据一致")
	}
}

// TestFragmentIncomplete 测试缺少部分分片时 complete() 返回 false。
func TestFragmentIncomplete(t *testing.T) {
	// 使用 2000 字节数据，分 2 片各 1000 字节
	data := make([]byte, 2000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fb := newFragmentBuffer(2000)

	// 只添加第一片（0-999），缺少第二片
	fb.addFragment(0, 1000, data[0:1000])

	if fb.complete() {
		t.Fatal("缺少分片时 complete() 应返回 false")
	}

	// 添加第二片后应 complete
	fb.addFragment(1000, 1000, data[1000:2000])
	if !fb.complete() {
		t.Fatal("所有分片已添加，complete() 应返回 true")
	}
}

// TestFragmentSingle 测试不分片（完整消息）的情况。
func TestFragmentSingle(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	fb := newFragmentBuffer(5)
	fb.addFragment(0, 5, data)

	if !fb.complete() {
		t.Fatal("单个分片添加后应 complete")
	}

	if !bytes.Equal(fb.assembled(), data) {
		t.Fatal("单个分片重组数据不一致")
	}
}

// TestFragmentAddOutOfRange 测试添加超出边界的分片返回 false。
func TestFragmentAddOutOfRange(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}

	fb := newFragmentBuffer(100)

	// 分片偏移超出总长度
	if fb.addFragment(100, 10, data[:10]) {
		t.Fatal("偏移超出总长应返回 false")
	}

	// 分片数据超出总长度
	if fb.addFragment(80, 30, data[:30]) {
		t.Fatal("数据超出总长应返回 false")
	}
}

// TestFragmentGapDetection 测试位掩码能正确检测分片间隙。
// 回归验证原 []bool 方案的假阳性 Bug 已修复。
func TestFragmentGapDetection(t *testing.T) {
	data := make([]byte, 3000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fb := newFragmentBuffer(3000)

	// 在 chunk 边界处添加 1 字节的分片，制造大量间隙
	// 这些位置在原 []bool 方案中会误触发 complete()=true
	fb.addFragment(0, 1, data[0:1])         // byte 0
	fb.addFragment(1399, 1, data[1399:1400]) // byte 1399
	fb.addFragment(1400, 1, data[1400:1401]) // byte 1400
	fb.addFragment(2799, 1, data[2799:2800]) // byte 2799
	fb.addFragment(2800, 1, data[2800:2801]) // byte 2800
	fb.addFragment(2999, 1, data[2999:3000]) // byte 2999

	if fb.complete() {
		t.Fatal("仅收到 6 个边界字节不应 complete")
	}

	// 填充所有间隙
	fb.addFragment(1, 1398, data[1:1399])     // [1, 1399)
	fb.addFragment(1401, 1398, data[1401:2799]) // [1401, 2799)
	fb.addFragment(2801, 198, data[2801:2999])  // [2801, 2999)

	if !fb.complete() {
		t.Fatal("所有间隙填充后应 complete")
	}
	if !bytes.Equal(fb.assembled(), data) {
		t.Fatal("填充间隙后重组数据与原始数据不一致")
	}
}

// TestFragmentBitmaskEdgeCases 测试位掩码在字节边界和对齐情况下的正确性。
func TestFragmentBitmaskEdgeCases(t *testing.T) {
	// 子用例 A: totalLen 为 8 的倍数 → 位掩码末尾字节恰好满
	t.Run("Align8", func(t *testing.T) {
		data := make([]byte, 8000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		fb := newFragmentBuffer(8000) // 8000 % 8 == 0
		if len(fb.received) != 1000 {
			t.Fatalf("掩码字节数应为 1000，实际 %d", len(fb.received))
		}
		fb.addFragment(0, 8000, data)
		if !fb.complete() {
			t.Fatal("应 complete")
		}
		// 最后一个字节应为全 0xFF
		if fb.received[999] != 0xFF {
			t.Fatal("最后一个掩码字节应为 0xFF")
		}
	})

	// 子用例 B: totalLen 非 8 的倍数 → 尾部不足 1 字节
	t.Run("NonAlign8", func(t *testing.T) {
		data := make([]byte, 8003)
		for i := range data {
			data[i] = byte(i % 256)
		}
		fb := newFragmentBuffer(8003) // 8003 % 8 == 3
		if len(fb.received) != 1001 {
			t.Fatalf("掩码字节数应为 1001，实际 %d", len(fb.received))
		}
		fb.addFragment(0, 8003, data)
		if !fb.complete() {
			t.Fatal("应 complete")
		}
		// 尾部 3 位的掩码: 0x07
		if fb.received[1000]&0x07 != 0x07 {
			t.Fatalf("尾部掩码应变 0x07，实际 0x%02x", fb.received[1000])
		}
	})

	// 子用例 C: tiny totalLen < 8
	t.Run("Tiny", func(t *testing.T) {
		data := []byte{0xAA, 0xBB, 0xCC}
		fb := newFragmentBuffer(3)
		if len(fb.received) != 1 {
			t.Fatalf("掩码字节数应为 1，实际 %d", len(fb.received))
		}
		fb.addFragment(0, 3, data)
		if !fb.complete() {
			t.Fatal("应 complete")
		}
		if fb.received[0]&0x07 != 0x07 {
			t.Fatalf("末 3 位应为 0x07，实际 0x%02x", fb.received[0])
		}
	})

	// 子用例 D: totalLen == 1
	t.Run("SingleByte", func(t *testing.T) {
		data := []byte{0x42}
		fb := newFragmentBuffer(1)
		fb.addFragment(0, 1, data)
		if !fb.complete() {
			t.Fatal("应 complete")
		}
		if fb.received[0]&0x01 != 0x01 {
			t.Fatalf("第 0 位应变 1，实际 0x%02x", fb.received[0])
		}
	})
}

// TestFragmentPendingCleanup 测试过期分片缓冲区被自动清理。
func TestFragmentPendingCleanup(t *testing.T) {
	c := &Conn{
		pendingFragments: make(map[uint16]*fragmentBuffer),
	}

	// 注入过期 fragment
	fb := &fragmentBuffer{
		totalLen:   1000,
		data:       make([]byte, 1000),
		received:   make([]byte, (1000+7)/8),
		numBytes:   1000,
		receivedAt: time.Now().Add(-2 * time.Minute),
	}
	c.pendingFragments[5] = fb

	c.cleanupStaleFragments(30 * time.Second)

	if _, ok := c.pendingFragments[5]; ok {
		t.Fatal("过期的 fragmentBuffer 应被清理")
	}
}

// TestFragmentCompleteOnCleanup 测试握手完成后 pendingFragments 被清空。
func TestFragmentCompleteOnCleanup(t *testing.T) {
	c := &Conn{
		pendingFragments: map[uint16]*fragmentBuffer{
			1: newFragmentBuffer(100),
			3: newFragmentBuffer(200),
		},
	}

	c.clearPendingFragments()

	if len(c.pendingFragments) != 0 {
		t.Fatalf("pendingFragments 应为空，实际长度 %d", len(c.pendingFragments))
	}
}
