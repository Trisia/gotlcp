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
	"errors"
	"fmt"
)

// 本文件定义携带 DTLCP 告警码的错误载体 alertError，
// 以及其构造函数 newAlertError 和告警码提取函数 alertForError。

// alertError 是携带 DTLCP 告警码的错误。
type alertError struct {
	// alert 表示该错误对应的 DTLCP 告警码。
	alert alert

	// err 表示被包装的原始错误。
	err error
}

// Error 返回错误描述。
func (e *alertError) Error() string { return e.err.Error() }

// Unwrap 返回被包装的错误。
func (e *alertError) Unwrap() error { return e.err }

// newAlertError 构造一个携带告警码 a 的错误。
func newAlertError(a alert, format string, args ...any) error {
	return &alertError{alert: a, err: fmt.Errorf(format, args...)}
}

// alertForError 返回错误链上携带的 DTLCP 告警码；
// 若整条链都未携带告警码，则返回 fallback。
func alertForError(err error, fallback alert) alert {
	var e *alertError
	if errors.As(err, &e) {
		return e.alert
	}
	return fallback
}

// sendAlertForError 按 err 携带的告警码发送告警，并原样返回 err。
//
// err 为 nil 时不发送任何告警并返回 nil；err 未携带告警码时使用 fallback。
func (c *Conn) sendAlertForError(err error, fallback alert) error {
	if err == nil {
		return nil
	}
	_ = c.sendAlert(alertForError(err, fallback))
	return err
}
