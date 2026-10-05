// Package model 定义面板的核心数据模型。
package model

import (
	"net"
	"strconv"
	"time"
)

// QuotaSpec 描述一个中转节点的流量配额。
type QuotaSpec struct {
	Enabled bool `json:"enabled"`
	// Period 取值为 daily / monthly / total。
	Period string `json:"period"`
	// Bytes 是周期内允许通过的流量（字节），0 表示不限。
	Bytes int64 `json:"bytes"`
	// Direction 取值为 total（双向合计）/ in（上行）/ out（下行）。
	Direction string `json:"direction"`
}

// RateSpec 描述限速（字节/秒）。
type RateSpec struct {
	Enabled bool  `json:"enabled"`
	InBps   int64 `json:"inBps"`
	OutBps  int64 `json:"outBps"`
}

// Upstream 描述出口代理（落地机的 SOCKS5 / HTTP）。
type Upstream struct {
	// Type 取值 socks5 / http / https。
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// Addr 返回 host:port。
func (u *Upstream) Addr() string { return net.JoinHostPort(u.Host, strconv.Itoa(u.Port)) }

// HasUpstream 判断节点是否配置了出口代理。
func (n *Node) HasUpstream() bool {
	return n.Upstream != nil && n.Upstream.Host != "" && n.Upstream.Port > 0
}

// Node 是一个中转或本机落地节点。
type Node struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	ListenPort int    `json:"listenPort"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
	// UDP 表示是否同时转发 UDP（QUIC 类协议必须开启）。
	UDP bool `json:"udp"`
	// Enabled 为 false 时该节点不生成任何服务。
	Enabled bool `json:"enabled"`
	// LandingLink 是落地机原始的 v2rayN 链接。
	LandingLink string `json:"landingLink"`
	// SNI / Host 为生成客户端链接时使用的覆盖值（留空表示沿用原链接）。
	SNI  string `json:"sni,omitempty"`
	Host string `json:"host,omitempty"`

	// SubToken 是该节点的专属订阅令牌，用于公开订阅入口按令牌定位节点。
	SubToken string `json:"subToken,omitempty"`

	// Mode 为节点类型：link（粘贴落地机链接，默认）/ gost（GOST 原生代理服务）。
	// 空值视为 link，兼容历史节点。
	Mode string `json:"mode,omitempty"`
	// GostLocal 表示代理服务直接运行在安装本面板的机器上；false 表示远程落地。
	GostLocal bool `json:"gostLocal,omitempty"`
	// GostProtocol / GostTransport 分别是 GOST 的代理处理协议与传输通道。
	// 旧节点缺省时按 ss + tcp 处理。
	GostProtocol  string `json:"gostProtocol,omitempty"`
	GostTransport string `json:"gostTransport,omitempty"`
	// GostUsername / GostPassword 是 HTTP、SOCKS、Relay 等协议的凭据。
	// Shadowsocks 使用 GostCipher 作为加密方法、GostPassword 作为密码。
	GostUsername string `json:"gostUsername,omitempty"`
	GostCipher   string `json:"gostCipher,omitempty"`
	GostPassword string `json:"gostPassword,omitempty"`
	// GostPath 是 WebSocket / gRPC 等通道的服务路径。
	GostPath string `json:"gostPath,omitempty"`

	// ---- VLESS+REALITY 节点（Mode=="reality"，由 sing-box 引擎承载）----
	// RealityUUID 是客户端 UUID；RealityPriv/RealityPub 是服务端密钥对（base64url）。
	// RealityShortID 为 8 位 hex；RealitySNI 是伪装域名（同时作为 handshake 目标）。
	RealityUUID string `json:"realityUuid,omitempty"`
	// 注意：列表/详情接口在 buildView 中剥离此字段，仅存储层保留。
	RealityPriv    string `json:"realityPriv,omitempty"`
	RealityPub     string `json:"realityPub,omitempty"`
	RealityShortID string `json:"realityShortId,omitempty"`
	RealitySNI     string `json:"realitySni,omitempty"`
	// RealityTransport 是 sing-box 入站的传输方式：空/"reality"（默认，VLESS+REALITY）、
	// "vmess"（VMess+TCP 无 TLS，给纯 TCP 端口转发类加速用：首包是 VMess 加密头，不含 HTTP Host / TLS SNI，
	// 国内云入口的未备案拦截看不到域名，所以能过）、
	// "ws-tls"（VLESS+WebSocket，源站自签 TLS）、"ws"（VLESS+WebSocket 明文）——给 CDN / HTTP 回源类加速用。
	// REALITY 的鉴权藏在 TLS ClientHello 里，经过会改写/重新发起 TLS 的中间设备必然失效。
	RealityTransport string `json:"realityTransport,omitempty"`
	// RealityWSPath 是 WebSocket 路径（加速兼容模式用，创建时自动生成）。
	RealityWSPath string `json:"realityWsPath,omitempty"`
	// AccelHost 是加速入口 host:port（可选）：填了就额外生成"经加速入口"的客户端链接。
	AccelHost string `json:"accelHost,omitempty"`

	// Upstream 是本机入站节点（GOST 本机落地 / REALITY）的出口代理：客户端到本机走入站协议加密，
	// 本机再经落地机的 SOCKS5 / HTTP 代理出站。nil 表示本机直出。
	Upstream *Upstream `json:"upstream,omitempty"`

	Quota QuotaSpec `json:"quota"`
	Rate  RateSpec  `json:"rate"`
	// ConnLimit 是并发连接数限制，0 表示不限。
	ConnLimit int `json:"connLimit"`
	// QuotaSince 是当前配额开始计数的起点（Unix 秒），用于面板侧流量核对与恢复。
	QuotaSince int64 `json:"quotaSince"`
	// ExpireAt 是节点到期时间（Unix 秒），0 表示永不到期。到期后节点停止对外服务
	// （效果等同停用），把到期时间改到将来即可恢复。前端按北京时间（UTC+8）录入与展示。
	ExpireAt int64 `json:"expireAt"`

	CreatedAt int64 `json:"createdAt"`
	UpdatedAt int64 `json:"updatedAt"`

	// TotalIn/TotalOut 是面板累计的流量（可重置）。
	TotalIn  uint64 `json:"totalIn"`
	TotalOut uint64 `json:"totalOut"`

	// CounterIn/CounterOut 是上次采样时引擎侧的累计计数原值（持久化，防面板重启后把
	// 引擎的整个生命周期计数重复累加进 TotalIn/Out）。CounterPid 记录引擎进程 pid：
	// pid 变化 = 引擎重启过，计数已归零，基线需重建。API 视图层剥离。
	CounterIn  uint64 `json:"counterIn"`
	CounterOut uint64 `json:"counterOut"`
	CounterPid int    `json:"counterPid"`
}

// ServiceNames 返回该节点在 gost 中对应的服务名。
// IsReality 判断节点是否由 sing-box 引擎承载。
func (n *Node) IsReality() bool { return n.Mode == "reality" }

// SBTransport 返回 sing-box 入站传输方式（规范化：空 = reality）。
func (n *Node) SBTransport() string {
	switch n.RealityTransport {
	case "ws", "ws-tls", "vmess":
		return n.RealityTransport
	}
	return "reality"
}

// Expired 判断节点是否已过到期时间；ExpireAt 为 0 表示永不到期。
func (n *Node) Expired() bool { return n.ExpireAt > 0 && time.Now().Unix() >= n.ExpireAt }

// Serving 表示节点应当对外提供服务：已启用且未到期。
// 所有"是否生成/保留引擎服务"的判断都应以此为准，而不是直接看 Enabled。
func (n *Node) Serving() bool { return n.Enabled && !n.Expired() }

func (n *Node) ServiceNames() []string {
	if n.IsReality() {
		return nil
	}
	names := []string{TCPName(n.ID)}
	// GOST 本机落地只有 Shadowsocks 的 UDP 扩展会生成第二个服务；
	// 远程中转和普通链接仍按 UDP 开关生成第二个透传服务。
	if n.UDP && (!n.GostLocal || n.Mode != "gost" || n.GostProtocol == "" || n.GostProtocol == "ss") {
		names = append(names, UDPName(n.ID))
	}
	return names
}

// TCPName / UDPName / QuotaName / LimiterName / CLimiterName 是 gost 内的资源命名。
func TCPName(id string) string      { return "node-" + id + "-tcp" }
func UDPName(id string) string      { return "node-" + id + "-udp" }
func QuotaName(id string) string    { return "quota-" + id }
func LimiterName(id string) string  { return "limiter-" + id }
func CLimiterName(id string) string { return "climiter-" + id }

// Point 是一个小时粒度的流量点。
type Point struct {
	TS  int64  `json:"ts"`
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}

// Live 是当前运行态信息（不落盘）。
type Live struct {
	CurrentConns uint64 `json:"currentConns"`
	TotalConns   uint64 `json:"totalConns"`
	TotalErrs    uint64 `json:"totalErrs"`
	// Running 表示 gost 中该节点的服务是否存在且处于运行状态。
	Running bool `json:"running"`
	// QuotaUsed/QuotaLimit 来自 gost 的配额计数（权威值，跨重启持久）。
	QuotaUsed  uint64 `json:"quotaUsed"`
	QuotaLimit uint64 `json:"quotaLimit"`
	// QuotaBlocked 表示流量超限导致服务被暂停。
	QuotaBlocked bool   `json:"quotaBlocked"`
	QuotaExpired bool   `json:"quotaExpired"`
	QuotaActive  bool   `json:"quotaActive"`
	QuotaUntil   int64  `json:"quotaUntil"`
	ServiceState string `json:"serviceState"`
}
