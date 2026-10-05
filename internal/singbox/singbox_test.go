package singbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gost-webui/internal/model"
)

// TestGeneratedConfigValid 保证面板生成的 reality 配置能被 sing-box 官方二进制接受。
// 若本机 /tmp 下没有测试用 sing-box 则跳过（CI/预览环境手动放置）。
func TestGeneratedConfigValid(t *testing.T) {
	bin := os.Getenv("SINGBOX_TEST_BIN")
	if bin == "" {
		t.Skip("SINGBOX_TEST_BIN not set")
	}
	priv, pub, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cred := &RealityCred{
		UUID: GenerateUUID(), PrivateKey: priv, PublicKey: pub,
		ShortID: GenerateShortID(), ServerName: "www.microsoft.com",
	}
	dir := t.TempDir()
	cf, kf, err := EnsureSelfSignedCert(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cred *RealityCred
		up   *model.Upstream
	}{
		{"reality-direct", cred, nil},
		{"reality-socks5", cred, &model.Upstream{Type: "socks5", Host: "1.2.3.4", Port: 1080, User: "u", Pass: "p"}},
		{"reality-https", cred, &model.Upstream{Type: "https", Host: "proxy.example.com", Port: 443}},
		{"ws-tls", &RealityCred{UUID: GenerateUUID(), Transport: "ws-tls", WSPath: GenerateWSPath()}, nil},
		{"ws", &RealityCred{UUID: GenerateUUID(), Transport: "ws", WSPath: GenerateWSPath()}, &model.Upstream{Type: "socks5", Host: "1.2.3.4", Port: 1080}},
		{"vmess", &RealityCred{UUID: GenerateUUID(), Transport: "vmess"}, nil},
	}
	for _, c := range cases {
		b, err := buildInstanceConfig("node-test", 24443, c.cred, "127.0.0.1:19399", "test-secret", c.up, cf, kf)
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, c.name+".json")
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
		if err != nil {
			t.Fatalf("sing-box check failed (%s): %v\n%s\nconfig:\n%s", c.name, err, out, b)
		}
	}
}

// 出口代理 → sing-box 出站：socks5 带鉴权；https 为 http + TLS（SNI 取代理域名）；无出口直出。
func TestOutboundFor(t *testing.T) {
	if ob := outboundFor(nil); ob["type"] != "direct" {
		t.Fatalf("nil upstream should be direct: %+v", ob)
	}
	ob := outboundFor(&model.Upstream{Type: "socks5", Host: "1.2.3.4", Port: 1080, User: "u", Pass: "p"})
	if ob["type"] != "socks" || ob["server"] != "1.2.3.4" || ob["server_port"] != 1080 || ob["username"] != "u" || ob["password"] != "p" || ob["tag"] != "out" {
		t.Fatalf("socks outbound = %+v", ob)
	}
	ob = outboundFor(&model.Upstream{Type: "https", Host: "proxy.example.com", Port: 443})
	tlsCfg, _ := ob["tls"].(map[string]any)
	if ob["type"] != "http" || ob["username"] != nil || tlsCfg == nil || tlsCfg["server_name"] != "proxy.example.com" {
		t.Fatalf("https outbound = %+v", ob)
	}
}

// TestRealityKeypairRoundtrip 校验密钥对生成格式与 sing-box/xray 兼容（base64url 43 字符）。
func TestRealityKeypairRoundtrip(t *testing.T) {
	priv, pub, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 43 || len(pub) != 43 {
		t.Fatalf("unexpected key lengths: priv=%d pub=%d", len(priv), len(pub))
	}
	sid := GenerateShortID()
	if len(sid) != 8 {
		t.Fatalf("short id len = %d, want 8", len(sid))
	}
	u := GenerateUUID()
	if len(u) != 36 || u[8] != '-' {
		t.Fatalf("bad uuid: %s", u)
	}
}

func TestClientURL(t *testing.T) {
	c := &RealityCred{UUID: "u-1", PublicKey: "PUB", ShortID: "ab12cd34", ServerName: "www.microsoft.com"}
	got := ClientURL(c, 8443, "1.2.3.4", "新加坡 节点")
	want := "vless://u-1@1.2.3.4:8443?encryption=none&security=reality&type=tcp&sni=www.microsoft.com&fp=chrome&pbk=PUB&sid=ab12cd34&flow=xtls-rprx-vision#%E6%96%B0%E5%8A%A0%E5%9D%A1%20%E8%8A%82%E7%82%B9"
	if got != want {
		t.Fatalf("ClientURL:\n got %s\nwant %s", got, want)
	}
}
