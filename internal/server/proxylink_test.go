package server

import (
	"encoding/base64"
	"net/url"
	"testing"

	"gost-webui/internal/model"
)

// 编辑落地代理时密码留空应沿用旧密码——包括旧链接是 v2rayN base64(user:pass)@host 写法的情况。
func TestProxyLinkKeepsPasswordFromBase64Link(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	old := &model.Node{Mode: "link", LandingLink: "socks://" + b64 + "@1.2.3.4:1080"}
	got, err := proxyLink(&proxyInput{Type: "socks5", Host: "1.2.3.4", Port: 1080, User: "alice"}, old)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if pass, _ := u.User.Password(); pass != "s3cret" {
		t.Fatalf("旧密码未沿用: %s", got)
	}
}

func TestProxyLinkDifferentUserDoesNotLeakOldPassword(t *testing.T) {
	old := &model.Node{Mode: "link", LandingLink: "socks5://alice:s3cret@1.2.3.4:1080"}
	got, err := proxyLink(&proxyInput{Type: "socks5", Host: "1.2.3.4", Port: 1080, User: "bob"}, old)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	if pass, _ := u.User.Password(); pass != "" {
		t.Fatalf("换账号时不应沿用旧密码: %s", got)
	}
}
