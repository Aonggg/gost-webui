package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gost-webui/internal/model"
	"gost-webui/internal/notify"
)

// 节点到期通知：仅在 未到期→到期 翻转时发一次，到期后持续观察不重复发（与 Notifier 冷却无关）；
// 延长后再次到期会再通知；面板启动时首次观察到的"早已到期"节点不补发；下线通知的原因应为"节点已到期"。
func TestNodeExpiredNotifyOnce(t *testing.T) {
	var mu sync.Mutex
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var form map[string]any
		_ = json.Unmarshal(b, &form)
		mu.Lock()
		texts = append(texts, fmt.Sprint(form["text"]))
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	newManager := func() *Manager {
		m := &Manager{
			Notify:            notify.New(slog.New(slog.NewTextHandler(io.Discard, nil))),
			TrafficThresholds: []int{80, 95},
			nodeRunning:       map[string]bool{},
			nodeUDP:           map[string]bool{},
			nodeConns:         map[string]uint64{},
			quotaLevel:        map[string]int{},
			windowKey:         map[string]int64{},
			nodeExpired:       map[string]bool{},
		}
		m.Notify.Update(notify.Config{
			Enabled: true, Token: "t", ChatID: "c",
			APIBase: srv.URL, Cooldown: 1, // Notifier 最小冷却 1s：用 sleep 跨过冷却，验证的是到期状态机本身的去重
			Events: map[string]bool{notify.EventNodeExpired: true, notify.EventNodeDown: true},
		})
		return m
	}
	collect := func() []string {
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), texts...)
		texts = nil
		return out
	}

	n := &model.Node{ID: "n1", Name: "香港", ListenPort: 45678, Enabled: true}
	m := newManager()

	// 未到期：运行中
	n.ExpireAt = time.Now().Unix() + 3600
	m.ObserveNodes(context.Background(), []*model.Node{n}, map[string]*model.Live{"n1": {Running: true}})
	if got := collect(); len(got) != 0 {
		t.Fatalf("未到期不应有通知: %v", got)
	}

	// 到期：采样器已拆服务（Running=false）→ 一条到期通知 + 一条下线通知（原因=节点已到期）
	// 1767196800 = 2026-01-01 00:00 北京时间（2025-12-31T16:00:00Z）
	n.ExpireAt = 1767196800
	m.ObserveNodes(context.Background(), []*model.Node{n}, map[string]*model.Live{"n1": {Running: false}})
	got := collect()
	if len(got) != 2 {
		t.Fatalf("期望 2 条（下线 + 到期），got %d: %v", len(got), got)
	}
	if !contains(got[0], "中转节点已下线") || !contains(got[0], "原因：节点已到期") {
		t.Fatalf("第 1 条应为到期原因的下线通知: %s", got[0])
	}
	if !contains(got[1], "节点已到期，已自动停用") || !contains(got[1], "2026-01-01 00:00（北京时间）") {
		t.Fatalf("第 2 条应为带北京时间的到期通知: %s", got[1])
	}

	// 持续到期：跨过冷却后再观察，仍不重复（去重来自状态机，不是冷却）
	time.Sleep(1100 * time.Millisecond)
	m.ObserveNodes(context.Background(), []*model.Node{n}, map[string]*model.Live{"n1": {Running: false}})
	if got := collect(); len(got) != 0 {
		t.Fatalf("到期后持续观察不应重复通知: %v", got)
	}

	// 延长到期时间后再次到期：再通知一次
	n.ExpireAt = time.Now().Unix() + 3600
	m.ObserveNodes(context.Background(), []*model.Node{n}, map[string]*model.Live{"n1": {Running: true}})
	if got := collect(); len(got) != 1 || !contains(got[0], "中转节点已上线") {
		t.Fatalf("延长后恢复应仅有上线通知: %v", got)
	}
	time.Sleep(1100 * time.Millisecond)
	n.ExpireAt = time.Now().Unix() - 1
	m.ObserveNodes(context.Background(), []*model.Node{n}, map[string]*model.Live{"n1": {Running: false}})
	if got := collect(); len(got) != 2 || !contains(got[1], "节点已到期，已自动停用") {
		t.Fatalf("延长后再次到期应再通知（下线 + 到期），got %d: %v", len(got), got)
	}

	// 新进程首次观察到早已到期的节点：不补发
	m2 := newManager()
	m2.ObserveNodes(context.Background(), []*model.Node{n}, map[string]*model.Live{"n1": {Running: false}})
	if got := collect(); len(got) != 0 {
		t.Fatalf("首次观察早已到期的节点不应通知: %v", got)
	}
}
