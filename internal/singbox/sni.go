package singbox

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// RealitySNIPool 是伪装域名候选池：大型站点、未被墙、支持 TLS 1.3 + HTTP/2。
// 留空伪装域名时从这里挑选，并先从本机探测确认可达。
var RealitySNIPool = []string{
	"www.microsoft.com",
	"www.apple.com",
	"www.amazon.com",
	"www.cloudflare.com",
	"gateway.icloud.com",
	"itunes.apple.com",
	"swdist.apple.com",
	"www.icloud.com",
	"www.samsung.com",
	"www.nvidia.com",
	"addons.mozilla.org",
	"www.bing.com",
	"www.tesla.com",
	"www.sony.com",
}

// probeTimeout 单个候选的 TLS 探测超时。
const probeTimeout = 4 * time.Second

// ProbeResult 是一个伪装域名的探测结果。
type ProbeResult struct {
	Host  string `json:"host"`
	OK    bool   `json:"ok"` // TLS 1.3 握手成功
	H2    bool   `json:"h2"` // 协商到 HTTP/2
	Error string `json:"error,omitempty"`
}

// ProbeRealityTarget 从本机向 host:443 发起 TLS 1.3 握手（ALPN 请求 h2），
// 确认该站点能作为 REALITY 握手目标：REALITY 要求目标支持 TLS 1.3，推荐 H2。
func ProbeRealityTarget(ctx context.Context, host string) ProbeResult {
	r := ProbeResult{Host: host}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: probeTimeout},
		Config: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	r.OK = st.Version == tls.VersionTLS13
	r.H2 = st.NegotiatedProtocol == "h2"
	return r
}

// PickRealitySNI 并发探测候选池，随机返回一个本机可达且支持 TLS 1.3 + H2 的伪装域名；
// 没有 H2 的退而求其次只要 TLS 1.3；全部不可达时返回错误。
func PickRealitySNI(ctx context.Context) (string, []ProbeResult, error) {
	results := make([]ProbeResult, len(RealitySNIPool))
	var wg sync.WaitGroup
	for i, h := range RealitySNIPool {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			results[i] = ProbeRealityTarget(ctx, h)
		}(i, h)
	}
	wg.Wait()

	var best, fallback []string
	for _, r := range results {
		switch {
		case r.OK && r.H2:
			best = append(best, r.Host)
		case r.OK:
			fallback = append(fallback, r.Host)
		}
	}
	if len(best) == 0 {
		best = fallback
	}
	if len(best) == 0 {
		return "", results, errors.New("候选伪装域名从本机均不可达（出站 443 是否被限制？），请手动填写")
	}
	return best[rand.IntN(len(best))], results, nil
}
