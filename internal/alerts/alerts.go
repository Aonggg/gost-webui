// Package alerts 负责事件检测与通知分发（节点上下线、流量预警、负载预警）。
package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"gost-webui/internal/model"
	"gost-webui/internal/notify"
	"gost-webui/internal/store"
	"gost-webui/internal/system"
)

// Manager 监控运行状态并按阈值发送通知。
type Manager struct {
	Notify *notify.Notifier
	Store  *store.Store
	Log    *slog.Logger

	mu          sync.Mutex
	metrics     system.Metrics
	metricsAt   time.Time
	nodeRunning map[string]bool
	nodeUDP     map[string]bool
	nodeConns   map[string]uint64
	quotaLevel  map[string]int
	windowKey   map[string]int64
	// nodeExpired 记录上次观察到的到期状态，仅在 未到期→到期 翻转时通知一次；
	// 面板重启不会对早已到期的节点重复通知。
	nodeExpired map[string]bool
	// TimeGuard 时间同步守护（可为 nil）：提供综合判定与最近处理说明
	TimeGuard *system.TimeGuard
	// clockUnsyncedSince 首次观察到时钟未同步的时刻；自动修复通常 1-2 分钟内解决，
	// 持续超过 clockGrace 仍未解决才通知（恢复后清零，再次失步会再通知一次）。
	clockUnsyncedSince time.Time
	clockWarned        bool

	TrafficThresholds []int
	CPUThreshold      float64
	MemThreshold      float64
	DiskThreshold     float64
}

// New 创建 Manager。
func New(st *store.Store, n *notify.Notifier, log *slog.Logger) *Manager {
	m := &Manager{
		Notify:            n,
		Store:             st,
		Log:               log,
		nodeRunning:       map[string]bool{},
		nodeUDP:           map[string]bool{},
		nodeConns:         map[string]uint64{},
		quotaLevel:        map[string]int{},
		windowKey:         map[string]int64{},
		nodeExpired:       map[string]bool{},
		TrafficThresholds: []int{80, 95},
		CPUThreshold:      90,
		MemThreshold:      90,
		DiskThreshold:     90,
	}
	m.Reload()
	return m
}

// Reload 从数据库读取通知与阈值配置。
func (m *Manager) Reload() {
	cfg := notify.Config{
		Enabled:  m.getBool("notify_enabled", false),
		Token:    m.get("notify_token", ""),
		ChatID:   m.get("notify_chat_id", ""),
		APIBase:  m.get("notify_api_base", "https://api.telegram.org"),
		Events:   notify.DefaultEvents(),
		Cooldown: m.getInt("notify_cooldown", 600),
	}
	if raw := m.get("notify_events", ""); raw != "" {
		var ev map[string]bool
		if json.Unmarshal([]byte(raw), &ev) == nil {
			cfg.Events = ev
		}
	}
	m.Notify.Update(cfg)

	if raw := m.get("alert_traffic_thresholds", ""); raw != "" {
		var v []int
		if json.Unmarshal([]byte(raw), &v) == nil && len(v) > 0 {
			m.TrafficThresholds = v
		}
	}
	m.CPUThreshold = m.getFloat("alert_cpu", 90)
	m.MemThreshold = m.getFloat("alert_mem", 90)
	m.DiskThreshold = m.getFloat("alert_disk", 90)
}

// Run 周期采集主机指标并检查负载阈值。
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	m.checkHost(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.checkHost(ctx)
		}
	}
}

// clockGrace 时钟未同步持续多久才通知（给自动修复留时间）。
const clockGrace = 5 * time.Minute

func (m *Manager) checkHost(ctx context.Context) {
	met := system.Read()
	m.mu.Lock()
	m.metrics = met
	m.metricsAt = time.Now()
	m.mu.Unlock()

	if !m.Notify.Enabled() {
		return
	}
	// 系统时钟未经 NTP 校准：时间漂移会让依赖时间戳/证书有效期的协议（VMess、SS2022、
	// 带时间差校验的 REALITY、TLS 证书签发）失败，并影响到期/配额判定。
	// TimeGuard 会先自动修复；超过宽限期仍未解决才提醒一次。
	if m.TimeGuard != nil {
		st := m.TimeGuard.Status()
		m.mu.Lock()
		warn := false
		switch st.State {
		case "unsynced":
			if m.clockUnsyncedSince.IsZero() {
				m.clockUnsyncedSince = time.Now()
			}
			if !m.clockWarned && time.Since(m.clockUnsyncedSince) >= clockGrace {
				warn, m.clockWarned = true, true
			}
		case "synced", "http":
			m.clockUnsyncedSince = time.Time{}
			m.clockWarned = false
		}
		m.mu.Unlock()
		if warn {
			// LastAction 是 apt / systemctl / HTTP 的原始输出，可能含 < & 等字符或很长：
			// Telegram 的 HTML 模式会直接拒收整条消息，这条一次性告警就没了
			text := fmt.Sprintf("<b>[GOST 面板] 服务器系统时间未同步</b>\n自动校时未能解决（持续 %d 分钟）。\n最近处理：%s\n"+
				"时间漂移会导致部分协议握手失败、节点“突然没网”。\n请到面板「系统设置 → 时间同步」查看并点击「立即校时」，或在服务器执行：timedatectl set-ntp true",
				int(clockGrace.Minutes()), html.EscapeString(lastLines(st.LastAction, 3, 600)))
			_ = m.Notify.Send(ctx, notify.EventLoadWarn, "clock", text)
		}
	}
	const miB = 1024 * 1024
	cpu := met.CPUPercent
	if m.CPUThreshold > 0 && cpu >= m.CPUThreshold {
		text := fmt.Sprintf("<b>[GOST 面板] 服务器 CPU 负载偏高</b>\n当前负载(1分钟)：%.2f（%d 核，约 %.1f%%）\n阈值：%.0f%%",
			met.Load1, met.CPUCount, cpu, m.CPUThreshold)
		_ = m.Notify.Send(ctx, notify.EventLoadWarn, "cpu", text)
	}
	if m.MemThreshold > 0 && met.MemPercent >= m.MemThreshold {
		text := fmt.Sprintf("<b>[GOST 面板] 服务器内存占用偏高</b>\n已用：%s / %s（%.1f%%）\n阈值：%.0f%%",
			fmtBytes(met.MemUsed*miB), fmtBytes(met.MemTotal*miB), met.MemPercent, m.MemThreshold)
		_ = m.Notify.Send(ctx, notify.EventLoadWarn, "mem", text)
	}
	if m.DiskThreshold > 0 && met.DiskPercent >= m.DiskThreshold {
		text := fmt.Sprintf("<b>[GOST 面板] 服务器磁盘占用偏高</b>\n已用：%s / %s（%.1f%%）\n阈值：%.0f%%",
			fmtBytes(met.DiskUsed), fmtBytes(met.DiskTotal), met.DiskPercent, m.DiskThreshold)
		_ = m.Notify.Send(ctx, notify.EventLoadWarn, "disk", text)
	}
}

// Metrics 返回最近一次采集的主机指标。
func (m *Manager) Metrics() (system.Metrics, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.metrics, m.metricsAt
}

// RefreshMetrics 立即重采一次主机指标（供改动系统状态的操作后即时刷新）。
func (m *Manager) RefreshMetrics() {
	met := system.Read()
	m.mu.Lock()
	m.metrics = met
	m.metricsAt = time.Now()
	m.mu.Unlock()
}

// ObserveNodes 检查节点状态变化与流量阈值，由采样器周期调用。
func (m *Manager) ObserveNodes(ctx context.Context, nodes []*model.Node, live map[string]*model.Live) {
	for _, n := range nodes {
		lv := live[n.ID]
		if lv == nil {
			continue
		}
		// 1) 上下线
		prev, seen := m.nodeRunning[n.ID]
		now := lv.Running && n.Enabled
		if seen && prev != now {
			if now {
				text := fmt.Sprintf("<b>[GOST 面板] 中转节点已上线</b>\n节点：%s\n端口：%d\n落地：%s:%d",
					n.Name, n.ListenPort, n.TargetHost, n.TargetPort)
				_ = m.Notify.Send(ctx, notify.EventNodeUp, n.ID, text)
			} else {
				reason := "服务已停止"
				if !n.Enabled {
					reason = "节点已被手动停用"
				} else if n.Expired() {
					reason = "节点已到期"
				} else if lv.QuotaBlocked {
					reason = "流量超限已暂停"
				}
				text := fmt.Sprintf("<b>[GOST 面板] 中转节点已下线</b>\n节点：%s\n端口：%d\n原因：%s",
					n.Name, n.ListenPort, reason)
				_ = m.Notify.Send(ctx, notify.EventNodeDown, n.ID, text)
			}
		}
		m.mu.Lock()
		m.nodeRunning[n.ID] = now
		m.mu.Unlock()

		// 2) 客户端上线/下线：仅在线人数 0↔N 状态翻转时各通知一次。
		//    （gost 的累计连接数把心跳、探测、短连接全算进去，按增量发必然刷屏）
		if prevCur, seen := m.nodeConns[n.ID]; seen {
			if prevCur == 0 && lv.CurrentConns > 0 {
				text := fmt.Sprintf("<b>[GOST 面板] 客户端已连接节点</b>\n节点：%s\n端口：%d\n当前在线：%d",
					n.Name, n.ListenPort, lv.CurrentConns)
				_ = m.Notify.Send(ctx, notify.EventNodeClient, n.ID+"|online", text)
			} else if prevCur > 0 && lv.CurrentConns == 0 {
				text := fmt.Sprintf("<b>[GOST 面板] 节点客户端已全部断开</b>\n节点：%s\n端口：%d",
					n.Name, n.ListenPort)
				_ = m.Notify.Send(ctx, notify.EventNodeClient, n.ID+"|offline", text)
			}
		}
		m.mu.Lock()
		m.nodeConns[n.ID] = lv.CurrentConns
		m.mu.Unlock()

		// 3) 流量超限暂停
		if lv.QuotaLimit > 0 && lv.QuotaBlocked {
			text := fmt.Sprintf("<b>[GOST 面板] 节点流量已达上限，已自动暂停</b>\n节点：%s\n已用：%s / %s（100%%）\n周期结束：%s",
				n.Name, fmtBytes(lv.QuotaUsed), fmtBytes(lv.QuotaLimit), tsDesc(lv.QuotaUntil))
			_ = m.Notify.Send(ctx, notify.EventQuotaBlocked, n.ID, text)
		}

		// 3b) 节点到期（延长到期时间后再次到期会再通知）
		expired := n.Expired()
		m.mu.Lock()
		prevExpired, seenExpired := m.nodeExpired[n.ID]
		m.nodeExpired[n.ID] = expired
		m.mu.Unlock()
		if seenExpired && !prevExpired && expired {
			text := fmt.Sprintf("<b>[GOST 面板] 节点已到期，已自动停用</b>\n节点：%s\n端口：%d\n到期时间：%s（北京时间）\n如需继续使用，请编辑节点延长到期时间",
				n.Name, n.ListenPort, beijingDesc(n.ExpireAt))
			_ = m.Notify.Send(ctx, notify.EventNodeExpired, n.ID, text)
		}

		// 4) 流量预警（按阈值档位，窗口切换后重置）
		if lv.QuotaLimit > 0 && !lv.QuotaBlocked {
			m.mu.Lock()
			if m.windowKey[n.ID] != lv.QuotaUntil {
				m.windowKey[n.ID] = lv.QuotaUntil
				m.quotaLevel[n.ID] = 0
			}
			level := m.quotaLevel[n.ID]
			m.mu.Unlock()

			pct := float64(lv.QuotaUsed) / float64(lv.QuotaLimit) * 100
			best := 0
			for _, th := range m.TrafficThresholds {
				if pct >= float64(th) && th > best {
					best = th
				}
			}
			if best > level {
				m.mu.Lock()
				m.quotaLevel[n.ID] = best
				m.mu.Unlock()
				text := fmt.Sprintf("<b>[GOST 面板] 节点流量预警</b>\n节点：%s\n已用：%s / %s（%.1f%%，已达 %d%% 阈值）\n周期结束：%s",
					n.Name, fmtBytes(lv.QuotaUsed), fmtBytes(lv.QuotaLimit), pct, best, tsDesc(lv.QuotaUntil))
				_ = m.Notify.Send(ctx, notify.EventTrafficWarn, fmt.Sprintf("%s-%d", n.ID, best), text)
			}
		}
	}
}

// NotifyPanelStart / NotifyPanelStop 面板生命周期通知。
func (m *Manager) NotifyPanelStart(ctx context.Context, url string) {
	text := fmt.Sprintf("<b>[GOST 面板] 面板已启动</b>\n时间：%s\n访问地址：%s",
		time.Now().Format("2006-01-02 15:04:05"), url)
	_ = m.Notify.Send(ctx, notify.EventPanelStart, "", text)
}

// NotifyPanelStop 面板停止通知。
func (m *Manager) NotifyPanelStop(ctx context.Context) {
	text := fmt.Sprintf("<b>[GOST 面板] 面板已停止</b>\n时间：%s", time.Now().Format("2006-01-02 15:04:05"))
	_ = m.Notify.Send(ctx, notify.EventPanelStop, "", text)
}

// nodeKind 返回节点类型的中文描述。
func nodeKind(n *model.Node) string {
	if n.Mode == "gost" {
		return "GOST 体系"
	}
	return "中转链接"
}

// NotifyNodeAdded 面板新增节点通知。
func (m *Manager) NotifyNodeAdded(ctx context.Context, n *model.Node) {
	text := fmt.Sprintf("<b>[GOST 面板] 已新增节点</b>\n节点：%s\n类型：%s（%s）\n中转端口：%d\n落地：%s:%d\n时间：%s",
		n.Name, nodeKind(n), n.Protocol, n.ListenPort, n.TargetHost, n.TargetPort,
		time.Now().Format("2006-01-02 15:04:05"))
	_ = m.Notify.Send(ctx, notify.EventNodeAdded, "", text)
}

// NotifyNodeDeleted 面板删除节点通知。
func (m *Manager) NotifyNodeDeleted(ctx context.Context, n *model.Node) {
	text := fmt.Sprintf("<b>[GOST 面板] 已删除节点</b>\n节点：%s\n类型：%s（%s）\n中转端口：%d\n落地：%s:%d\n时间：%s",
		n.Name, nodeKind(n), n.Protocol, n.ListenPort, n.TargetHost, n.TargetPort,
		time.Now().Format("2006-01-02 15:04:05"))
	_ = m.Notify.Send(ctx, notify.EventNodeDeleted, "", text)
}

// ---------- 设置读取辅助 ----------

func (m *Manager) get(key, def string) string {
	if v, ok := m.Store.GetSetting(key); ok {
		return v
	}
	return def
}

func (m *Manager) getBool(key string, def bool) bool {
	if v, ok := m.Store.GetSetting(key); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func (m *Manager) getInt(key string, def int) int {
	if v, ok := m.Store.GetSetting(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func (m *Manager) getFloat(key string, def float64) float64 {
	if v, ok := m.Store.GetSetting(key); ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func fmtBytes(n uint64) string {
	f := float64(n)
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}

func tsDesc(ts int64) string {
	if ts <= 0 {
		return "不重置"
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04")
}

var beijing = time.FixedZone("CST", 8*3600)

// beijingDesc 按北京时间格式化 Unix 秒（到期时间以北京时区为准，与服务器时区无关）。
func beijingDesc(ts int64) string {
	return time.Unix(ts, 0).In(beijing).Format("2006-01-02 15:04")
}

// MaskToken 脱敏 Token。
func MaskToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		if t == "" {
			return ""
		}
		return "****"
	}
	return t[:4] + "****" + t[len(t)-4:]
}

// lastLines 取 s 的最后 n 行并限制总长度（通知正文用）。
func lastLines(s string, n, maxLen int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, "\n")
	if r := []rune(out); len(r) > maxLen {
		out = "…" + string(r[len(r)-maxLen:])
	}
	return out
}
