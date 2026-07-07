// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"bytes"
	"testing"
)

// TestFragmentReassembly 测试分片正常收齐后可以正确重组。
func TestFragmentReassembly(t *testing.T) {
	// 构建 3000 字节的原始数据
	data := make([]byte, 3000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fb := newFragmentBuffer(3000, 1400)

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

	fb := newFragmentBuffer(2800, 1400)

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

	fb := newFragmentBuffer(2000, 1000)

	// 先以 1000 为单位添加两个分片
	fb.addFragment(0, 1000, data[0:1000])
	fb.addFragment(1000, 1000, data[1000:2000])
	if !fb.complete() {
		t.Fatal("两个分片添加后应 complete")
	}

	// PMTU 变小导致重分片为 4 个 500 字节分片
	// 添加重叠分片，覆盖原有的
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
}

// TestFragmentIncomplete 测试缺少部分分片时 complete() 返回 false。
func TestFragmentIncomplete(t *testing.T) {
	// 使用 2000 字节数据，分 2 片各 1000 字节
	data := make([]byte, 2000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fb := newFragmentBuffer(2000, 1000)

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

	fb := newFragmentBuffer(5, 1400)
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

	fb := newFragmentBuffer(100, 50)

	// 分片偏移超出总长度
	if fb.addFragment(100, 10, data[:10]) {
		t.Fatal("偏移超出总长应返回 false")
	}

	// 分片数据超出总长度
	if fb.addFragment(80, 30, data[:30]) {
		t.Fatal("数据超出总长应返回 false")
	}
}
