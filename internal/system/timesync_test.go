package system

import (
	"context"
	"crypto/x509"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// trustHTTPTestCert 让证书链校验信任 httptest 的自签证书（它对 127.0.0.1 有效，有效期 1970–2084）。
func trustHTTPTestCert(t *testing.T, srv *httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	orig := httpTimeRoots
	httpTimeRoots = pool
	t.Cleanup(func() { httpTimeRoots = orig })
}

// HTTP 校时：取多个站点 Date 头的中位数；单个站点异常（时间离谱 / 无 Date / 不可达）不影响结果。
func TestHTTPTimeOffsetMedian(t *testing.T) {
	dateServer := func(skew time.Duration) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Date", time.Now().Add(skew).UTC().Format(http.TimeFormat))
		}))
	}
	// 三个正常站点认为"真实时间"比本机快 5 分钟（即本机慢 300 秒），一个站点离谱，一个站点没有 Date
	good1, good2, good3 := dateServer(5*time.Minute), dateServer(5*time.Minute+time.Second), dateServer(5*time.Minute-time.Second)
	bogus := dateServer(-10 * 24 * time.Hour)
	noDate := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = nil // 禁止 net/http 自动补 Date
	}))
	defer good1.Close()
	defer good2.Close()
	defer good3.Close()
	defer bogus.Close()
	defer noDate.Close()

	trustHTTPTestCert(t, good1)
	orig := httpTimeSources
	httpTimeSources = []string{bogus.URL, good1.URL, noDate.URL, good2.URL, "https://127.0.0.1:9/", good3.URL}
	defer func() { httpTimeSources = orig }()

	off, src, err := HTTPTimeOffset(context.Background())
	if err != nil {
		t.Fatalf("HTTPTimeOffset: %v", err)
	}
	// 本机 - 真实 = -300 秒（允许 ±3 秒：Date 头秒级精度 + 往返）
	if math.Abs(off.Seconds()+300) > 3 {
		t.Fatalf("offset = %v, want about -300s (src=%s)", off, src)
	}
}

func TestHTTPTimeOffsetAllUnreachable(t *testing.T) {
	orig := httpTimeSources
	httpTimeSources = []string{"https://127.0.0.1:9/", "https://127.0.0.1:10/"}
	defer func() { httpTimeSources = orig }()
	if _, _, err := HTTPTimeOffset(context.Background()); err == nil {
		t.Fatal("expected error when every source is unreachable")
	}
}

// 证书链校验：站点证书不被信任（链路被劫持 / 中间人伪造 Date 头）时样本一律丢弃，不能据此拨钟。
func TestHTTPTimeOffsetRejectsUntrustedChain(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().Add(-365*24*time.Hour).UTC().Format(http.TimeFormat))
	}))
	defer srv.Close()
	orig := httpTimeSources
	httpTimeSources = []string{srv.URL, srv.URL}
	defer func() { httpTimeSources = orig }()
	// 根证书池为空：等价于攻击者拿着一张谁也不认的证书
	origRoots := httpTimeRoots
	httpTimeRoots = x509.NewCertPool()
	defer func() { httpTimeRoots = origRoots }()

	_, _, err := HTTPTimeOffset(context.Background())
	if err == nil || !strings.Contains(err.Error(), "证书校验") {
		t.Fatalf("expected certificate rejection, got %v", err)
	}
}

// 只有一个可信样本时不采信（防单点伪造）。
func TestHTTPTimeOffsetNeedsAgreement(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().Add(5*time.Minute).UTC().Format(http.TimeFormat))
	}))
	defer srv.Close()
	trustHTTPTestCert(t, srv)
	orig := httpTimeSources
	httpTimeSources = []string{srv.URL, "https://127.0.0.1:9/"}
	defer func() { httpTimeSources = orig }()
	if _, _, err := HTTPTimeOffset(context.Background()); err == nil {
		t.Fatal("expected error with a single trusted sample")
	}
}

// 综合判定：内核已同步 → synced；未同步但近期 HTTP 校验偏差很小 → http；否则 unsynced；读不到 → unknown。
func TestComputeState(t *testing.T) {
	now := time.Now()
	yes, no := true, false
	small, big := 0.5, 40.0
	cases := []struct {
		name   string
		synced *bool
		off    *float64
		at     time.Time
		want   string
	}{
		{"kernel synced", &yes, nil, time.Time{}, "synced"},
		{"unknown", nil, &small, now, "unknown"},
		{"http recent small", &no, &small, now.Add(-10 * time.Minute), "http"},
		{"http stale", &no, &small, now.Add(-3 * time.Hour), "unsynced"},
		{"http big offset", &no, &big, now, "unsynced"},
		{"never checked", &no, nil, time.Time{}, "unsynced"},
	}
	for _, c := range cases {
		if got := computeState(TimeStatus{Synced: c.synced}, c.off, c.at, now); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
