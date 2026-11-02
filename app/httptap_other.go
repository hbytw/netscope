//go:build !linux

package main

// 非 Linux 平台（开发机 Windows 等）没有 AF_PACKET，抓包能力为空实现。
// 真机（OpenWrt/Linux）走 httptap_linux.go。

func (a *App) StartHTTPTap() error { return nil }
func (a *App) StopHTTPTap()        {}
func HTTPTapRunning() bool         { return false }
