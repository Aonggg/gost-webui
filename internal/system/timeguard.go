package system

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"
)

// TimeGuard 周期检查系统时钟同步状态，未同步时自动修复（可关），
// 并对外提供状态快照与手动修复入口。
type TimeGuard struct {
	Log *slog.Logger
	// AutoFix 是否允许自动修复（读取面板设置）。
	AutoFix func() bool
	// Timezone 期望的系统时区（空 = 不动）。
	Timezone func() string

	mu           sync.Mutex
	status       TimeStatus
	httpOffset   *float64
	httpAt       time.Time
	lastAction   string
	lastActionAt time.Time
	fixing       bool
	attempts     int
	nextFix      time.Time
}

// 自动修复的退避间隔：失败越多试得越疏，封顶 1 小时。
var fixBackoff = []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}

// httpRecheck NTP 不可用、靠 HTTP 校时时的复查间隔（时钟漂移一般每小时不到 1 秒）。
const httpRecheck = 30 * time.Minute

// NewTimeGuard 创建守护；autoFix / timezone 为 nil 时分别视为"总是自动修复"/"不动时区"。
func NewTimeGuard(log *slog.Logger, autoFix func() bool, timezone func() string) *TimeGuard {
	if autoFix == nil {
		autoFix = func() bool { return true }
	}
	if timezone == nil {
		timezone = func() string { return "" }
	}
	g := &TimeGuard{Log: log, AutoFix: autoFix, Timezone: timezone}
	g.refresh()
	return g
}

// Run 每分钟刷新一次状态，需要时触发自动修复。
func (g *TimeGuard) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	g.maybeFix(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.refresh()
			g.maybeFix(ctx)
		}
	}
}

// Status 返回当前状态快照（含综合判定 State）。
func (g *TimeGuard) Status() TimeStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

// Refresh 立即重读系统状态并返回（API 查询用，避免最多 1 分钟的滞后）。
func (g *TimeGuard) Refresh() TimeStatus {
	g.refresh()
	return g.Status()
}

// State 返回综合判定：synced / http / unsynced / unknown。
func (g *TimeGuard) State() string { return g.Status().State }

// FixNow 立即执行一次修复（手动触发），返回逐步说明。
func (g *TimeGuard) FixNow(ctx context.Context) (string, error) {
	g.mu.Lock()
	if g.fixing {
		g.mu.Unlock()
		return "", ErrTimeFixBusy
	}
	g.fixing = true
	g.mu.Unlock()
	return g.fix(ctx, true)
}

// ErrTimeFixBusy 表示已有修复在进行中。
var ErrTimeFixBusy = errors.New("正在校时中，请稍候")

// refresh 重读系统状态并更新综合判定。
func (g *TimeGuard) refresh() {
	st := ReadTimeStatus()
	g.mu.Lock()
	defer g.mu.Unlock()
	st.HTTPOffset = g.httpOffset
	if !g.httpAt.IsZero() {
		st.HTTPCheckedAt = g.httpAt.Unix()
	}
	st.LastAction = g.lastAction
	if !g.lastActionAt.IsZero() {
		st.LastActionAt = g.lastActionAt.Unix()
	}
	st.State = computeState(st, g.httpOffset, g.httpAt, time.Now())
	g.status = st
}

// computeState 综合内核同步标志与 HTTP 校验结果给出状态。
func computeState(st TimeStatus, httpOffset *float64, httpAt time.Time, now time.Time) string {
	if st.Synced == nil {
		return "unknown"
	}
	if *st.Synced {
		return "synced"
	}
	if httpOffset != nil && now.Sub(httpAt) < 2*httpRecheck && math.Abs(*httpOffset) <= maxHTTPStep.Seconds() {
		return "http"
	}
	return "unsynced"
}

// maybeFix 根据状态与退避决定是否后台触发一次自动修复。
func (g *TimeGuard) maybeFix(ctx context.Context) {
	if !g.AutoFix() {
		return
	}
	g.mu.Lock()
	state := g.status.State
	due := time.Now().After(g.nextFix)
	recheck := state == "http" && time.Since(g.httpAt) >= httpRecheck
	if g.fixing || !due || (state != "unsynced" && !recheck) {
		g.mu.Unlock()
		return
	}
	g.fixing = true
	g.mu.Unlock()
	go func() { _, _ = g.fix(ctx, false) }()
}

// fix 执行 Fix 并记录结果；调用前必须已把 fixing 置 true。
func (g *TimeGuard) fix(ctx context.Context, manual bool) (string, error) {
	fctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	res, err := Fix(fctx, g.Timezone(), 20*time.Second)
	report := res.Report()

	g.mu.Lock()
	if res.HTTPOffset != nil {
		off := *res.HTTPOffset
		g.httpOffset = &off
		g.httpAt = time.Now()
	}
	last := report
	if err != nil {
		last = err.Error() + "\n" + report
		g.attempts++
	} else {
		g.attempts = 0
	}
	g.lastAction = strings.TrimSpace(last)
	g.lastActionAt = time.Now()
	g.nextFix = time.Now().Add(fixBackoff[min(g.attempts, len(fixBackoff)-1)])
	g.fixing = false
	g.mu.Unlock()

	g.refresh()
	kind := "自动"
	if manual {
		kind = "手动"
	}
	if err != nil {
		g.Log.Warn(kind+"校时失败", "err", err, "detail", report)
	} else {
		g.Log.Info(kind+"校时完成", "detail", report)
	}
	return report, err
}
