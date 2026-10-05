package gostmgr

import (
	"strings"
	"testing"
	"time"

	"gost-webui/internal/model"
)

func TestGostClientURLLegacySSDefaults(t *testing.T) {
	n := &model.Node{
		Mode:         "gost",
		Name:         "旧节点",
		GostCipher:   "aes-256-gcm",
		GostPassword: "secret",
	}
	got, err := GostClientURL(n, "2001:db8::1", 8388)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "ss://") || !strings.Contains(got, "@[2001:db8::1]:8388") {
		t.Fatalf("unexpected SS URL: %s", got)
	}
}

func TestGostClientURLLayeredTransport(t *testing.T) {
	n := &model.Node{
		Mode:          "gost",
		GostLocal:     true,
		GostProtocol:  "socks5",
		GostTransport: "wss",
		GostUsername:  "alice",
		GostPassword:  "p@ss",
		GostPath:      "/edge",
	}
	got, err := GostClientURL(n, "proxy.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "socks5+wss://alice:p%40ss@proxy.example.com:443") || !strings.Contains(got, "path=%2Fedge") {
		t.Fatalf("unexpected layered URL: %s", got)
	}
}

func TestGostClientURLSSHUsesChannelPassword(t *testing.T) {
	n := &model.Node{
		Mode:          "gost",
		GostLocal:     true,
		GostProtocol:  "socks4",
		GostTransport: "ssh",
		GostUsername:  "alice",
		GostPassword:  "secret",
	}
	got, err := GostClientURL(n, "proxy.example.com", 2222)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "socks4+ssh://alice:secret@proxy.example.com:2222") {
		t.Fatalf("SSH channel password missing from URL: %s", got)
	}
	services := BuildGostProxyServices(n, 2222)
	if len(services) != 1 || services[0].Handler.Auth != nil || services[0].Listener.Auth == nil || services[0].Listener.Auth.Password != "secret" {
		t.Fatalf("bad SSH channel auth: %#v", services)
	}
}

func TestDTLSCompatibilityDefaults(t *testing.T) {
	n := &model.Node{
		Mode:          "gost",
		GostLocal:     true,
		GostProtocol:  "relay",
		GostTransport: "dtls",
		GostUsername:  "u",
		GostPassword:  "p",
	}
	got, err := GostClientURL(n, "proxy.example.com", 9443)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "flightInterval=500ms") {
		t.Fatalf("DTLS client URL is missing flight interval: %s", got)
	}
	services := BuildGostProxyServices(n, 9443)
	if services[0].Listener.Metadata["flightInterval"] != "500ms" || services[0].Listener.Metadata["mtu"] != 1200 {
		t.Fatalf("DTLS listener is missing flight interval: %#v", services[0].Listener.Metadata)
	}
}

func TestValidateGostNodeRestrictions(t *testing.T) {
	tests := []struct {
		name string
		node model.Node
	}{
		{"raw remote", model.Node{Mode: "gost", GostProtocol: "relay", GostTransport: "icmp"}},
		{"udp http", model.Node{Mode: "gost", GostLocal: true, GostProtocol: "http", GostTransport: "udp"}},
		{"http2 wrong channel", model.Node{Mode: "gost", GostLocal: true, GostProtocol: "http2", GostTransport: "tls"}},
		{"ss over ssh", model.Node{Mode: "gost", GostLocal: true, GostProtocol: "ss", GostTransport: "ssh"}},
		{"udp addon collision", model.Node{Mode: "gost", GostLocal: true, GostProtocol: "ss", GostTransport: "quic", UDP: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateGostNode(&tt.node); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestBuildConfigLocalAndRemoteGost(t *testing.T) {
	local := &model.Node{
		ID: "local", Mode: "gost", Enabled: true, GostLocal: true,
		ListenPort: 1443, GostProtocol: "socks5", GostTransport: "ws",
		GostUsername: "u", GostPassword: "p", GostPath: "/gost",
	}
	remote := &model.Node{
		ID: "remote", Mode: "gost", Enabled: true,
		ListenPort: 2443, TargetHost: "land.example.com", TargetPort: 443,
		GostProtocol: "relay", GostTransport: "quic", GostUsername: "u", GostPassword: "p",
	}
	cfg := BuildConfig([]*model.Node{local, remote}, BuildOptions{})
	if len(cfg.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(cfg.Services))
	}
	ls := cfg.Services[0]
	if ls.Handler.Type != "socks5" || ls.Listener.Type != "ws" || ls.Forwarder != nil {
		t.Fatalf("bad local service: %#v", ls)
	}
	if ls.Handler.Auth == nil || ls.Handler.Auth.Username != "u" || ls.Listener.Metadata["path"] != "/gost" {
		t.Fatalf("bad local auth/metadata: %#v %#v", ls.Handler, ls.Listener)
	}
	rs := cfg.Services[1]
	if rs.Handler.Type != "udp" || rs.Listener.Type != "udp" || rs.Forwarder == nil || rs.Forwarder.Nodes[0].Addr != "land.example.com:443" {
		t.Fatalf("bad remote service: %#v", rs)
	}
}

func TestBuildConfigLocalShadowsocksUDP(t *testing.T) {
	n := &model.Node{
		ID: "ss", Mode: "gost", Enabled: true, GostLocal: true, UDP: true,
		ListenPort: 8388, GostProtocol: "ss", GostTransport: "tcp",
		GostCipher: "aes-256-gcm", GostPassword: "secret",
	}
	cfg := BuildConfig([]*model.Node{n}, BuildOptions{})
	if len(cfg.Services) != 2 {
		t.Fatalf("services = %d, want TCP+UDP", len(cfg.Services))
	}
	if cfg.Services[0].Handler.Type != "ss" || cfg.Services[1].Handler.Type != "ssu" || cfg.Services[1].Listener.Type != "udp" {
		t.Fatalf("unexpected SS services: %#v", cfg.Services)
	}
}

// 到期节点不得生成任何 gost 服务（等同停用）；未到期的照常生成，ExpireAt=0 永不到期。
func TestBuildConfigSkipsExpiredNode(t *testing.T) {
	mk := func(id string, expireAt int64) *model.Node {
		return &model.Node{
			ID: id, Mode: "gost", Enabled: true, GostLocal: true, ExpireAt: expireAt,
			ListenPort: 8388, GostProtocol: "ss", GostTransport: "tcp",
			GostCipher: "aes-256-gcm", GostPassword: "secret",
		}
	}
	now := time.Now().Unix()
	cfg := BuildConfig([]*model.Node{mk("expired", now-1), mk("edge", now), mk("future", now+60), mk("never", 0)}, BuildOptions{})
	var names []string
	for _, s := range cfg.Services {
		names = append(names, s.Name)
	}
	want := []string{model.TCPName("future"), model.TCPName("never")}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("services = %v, want %v", names, want)
	}
}

// 本机落地 + 出口代理：生成 chain 并让服务 handler 引用；出口只走 TCP，不生成 UDP 服务；
// https 出口为 http 连接器 + TLS 拨号。远程落地/无出口的节点不产生 chain。
func TestBuildConfigUpstreamChain(t *testing.T) {
	n := &model.Node{
		ID: "up", Mode: "gost", Enabled: true, GostLocal: true, UDP: true,
		ListenPort: 8388, GostProtocol: "ss", GostTransport: "tcp",
		GostCipher: "aes-256-gcm", GostPassword: "secret",
		Upstream: &model.Upstream{Type: "socks5", Host: "1.2.3.4", Port: 1080, User: "u", Pass: "p"},
	}
	plain := &model.Node{
		ID: "plain", Mode: "gost", Enabled: true, GostLocal: true,
		ListenPort: 8389, GostProtocol: "ss", GostTransport: "tcp",
		GostCipher: "aes-256-gcm", GostPassword: "secret",
	}
	cfg := BuildConfig([]*model.Node{n, plain}, BuildOptions{})
	if len(cfg.Chains) != 1 || cfg.Chains[0].Name != ChainName("up") {
		t.Fatalf("chains = %+v, want one chain for node up", cfg.Chains)
	}
	hop := cfg.Chains[0].Hops[0].Nodes[0]
	if hop.Addr != "1.2.3.4:1080" || hop.Connector.Type != "socks5" || hop.Connector.Auth.Username != "u" || hop.Dialer.Type != "tcp" {
		t.Fatalf("chain node = %+v", hop)
	}
	var names []string
	for _, s := range cfg.Services {
		names = append(names, s.Name+":"+s.Handler.Chain)
	}
	want := model.TCPName("up") + ":" + ChainName("up") + "," + model.TCPName("plain") + ":"
	if strings.Join(names, ",") != want {
		t.Fatalf("services = %v, want %s（出口代理不生成 UDP 服务）", names, want)
	}

	n.Upstream = &model.Upstream{Type: "https", Host: "proxy.example.com", Port: 443}
	ch := BuildChain(n)
	hop = ch.Hops[0].Nodes[0]
	if hop.Connector.Type != "http" || hop.Connector.Auth != nil || hop.Dialer.Type != "tls" || hop.Dialer.TLS == nil || hop.Dialer.TLS.ServerName != "proxy.example.com" || !hop.Dialer.TLS.Secure {
		t.Fatalf("https chain node = %+v", hop)
	}
}

func TestBuildLandingGeneric(t *testing.T) {
	n := &model.Node{
		ID: "relay", Mode: "gost", TargetPort: 9443,
		GostProtocol: "relay", GostTransport: "grpc", GostUsername: "u", GostPassword: "p", GostPath: "/rpc",
	}
	yml, run, err := BuildLanding(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"type: relay", "type: grpc", "path: /rpc", "username: u"} {
		if !strings.Contains(yml, want) {
			t.Fatalf("missing %q in:\n%s", want, yml)
		}
	}
	if !strings.Contains(run, "relay+grpc://u:p@:9443") || !strings.Contains(run, "path=%2Frpc") {
		t.Fatalf("unexpected run command: %s", run)
	}
}
