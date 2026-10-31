package main

// 前端静态资源内嵌。web/ 目录由前端队友维护，本文件只负责暴露只读文件系统。
// 支持两种来源：
//   - 默认：go:embed 内嵌进二进制（部署到路由器时单文件即可用）；
//   - -web <dir>：开发时直接从磁盘目录读取（改完前端刷新即可见）。

import (
	"embed"
	"io/fs"
	"os"
)

//go:embed all:web
var embeddedWeb embed.FS

// buildWebFS 返回前端资源根目录。
// webDir 非空时使用 os.DirFS(webDir)，否则返回内嵌的 web/ 子目录。
func buildWebFS(webDir string) fs.FS {
	if webDir != "" {
		return os.DirFS(webDir)
	}
	sub, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		return embeddedWeb
	}
	return sub
}
