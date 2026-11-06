package main

import "testing"

// TestBlockTargetHost 手工封禁入口的 URL/域名解析与校验。
// 口径：完整 URL 取主机名（去 scheme/路径/端口）；IP 与非法格式一律拒绝
// （IP 走设备/目标封禁，域名封禁只按域名生效）。
func TestBlockTargetHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"http://evil.com/a/b?x=1", "evil.com", true},
		{"https://Evil.COM:8443/path", "evil.com", true},
		{"evil.com", "evil.com", true},
		{"evil.com.", "evil.com", true},
		{"  sub.example.cn  ", "sub.example.cn", true},
		{"xn--fiq228c.example", "xn--fiq228c.example", true},
		{"http://192.168.1.1/x", "", false}, // IP 不走域名封禁
		{"10.0.0.1", "", false},
		{"", "", false},
		{"   ", "", false},
		{"http://", "", false},
		{"not a domain", "", false},
		{"localhost", "", false}, // 至少两级域名
		{"-bad.com", "", false},
		{"bad-.com", "", false},
	}
	for _, c := range cases {
		got, err := blockTargetHost(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("blockTargetHost(%q) 报错: %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("blockTargetHost(%q) = %q; want %q", c.in, got, c.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("blockTargetHost(%q) = %q; 应当报错", c.in, got)
		}
	}
}

// TestManualDomainBlockStore 手工封禁列表的增删查与规范化（小写/去尾点/去重）。
func TestManualDomainBlockStore(t *testing.T) {
	a := newTestApp(t, true)
	if !a.store.AddDomainBlock("EVIL.com") {
		t.Fatal("首次添加应成功")
	}
	if !a.store.IsDomainBlock("evil.com") {
		t.Fatal("应按小写规范化存储")
	}
	if a.store.AddDomainBlock("evil.com.") {
		t.Fatal("重复添加（大小写/尾点不同）应返回 false")
	}
	if got := len(a.store.DomainBlocks()); got != 1 {
		t.Fatalf("列表长度 = %d; want 1", got)
	}
	if !a.store.RemoveDomainBlock("EVIL.COM") {
		t.Fatal("移除应成功（大小写不敏感）")
	}
	if a.store.RemoveDomainBlock("evil.com") {
		t.Fatal("重复移除应返回 false")
	}
	if a.store.IsDomainBlock("evil.com") {
		t.Fatal("移除后不应再命中")
	}
	if a.store.AddDomainBlock("") {
		t.Fatal("空域名应拒绝")
	}
}
