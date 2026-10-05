package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gost-webui/internal/alerts"
	"gost-webui/internal/config"
	"gost-webui/internal/notify"
	"gost-webui/internal/system"
)

// handleSystemInfo 返回面板/主机/系统配置信息。
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	gst := s.ctl.Gost.Status()
	var met system.Metrics
	var metAt time.Time
	if s.ctl.Alerts != nil {
		met, metAt = s.ctl.Alerts.Metrics()
	}

	listen := s.effectiveListen()
	basePath := s.effectiveBasePath()

	writeJSON(w, http.StatusOK, map[string]any{
		"panel": map[string]any{
			"version":     Version,
			"listen":      listen,
			"basePath":    basePath,
			"startedAt":   s.started.Unix(),
			"uptime":      int64(time.Since(s.started).Seconds()),
			"runtimeOS":   met.RuntimeOS,
			"runtimeArch": met.RuntimeArch,
			"configFile":  cfgPath,
		},
		"host": map[string]any{
			"metrics":   met,
			"sampledAt": metAt.Unix(),
		},
		"gost": map[string]any{
			"process":    gst,
			"reachable":  s.ctl.GostReachable(),
			"configFile": s.cfg.Gost.ConfigFile,
			"logFile":    s.cfg.Gost.LogFile,
			"bin":        s.cfg.Gost.Bin,
		},
		"publicHost":        s.publicHost(),
		"publicHostPrivate": isPrivateHost(s.publicHost()),
	})
}

// Version 面板版本号（由 main 注入）。
var Version = "1.0.0"

// cfgPath 配置文件路径（由 main 注入）。
var cfgPath = "/etc/gost-webui/panel.yml"

// SetConfigPath 设置配置文件路径。
func SetConfigPath(p string) { cfgPath = p }

func (s *Server) effectiveListen() string {
	if v, ok := s.ctl.Store.GetSetting("panel_listen"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return s.cfg.Listen
}

func (s *Server) effectiveBasePath() string {
	if v, ok := s.ctl.Store.GetSetting("base_path"); ok {
		return config.NormalizeBasePath(v)
	}
	return s.basePath
}

// handleSystemUpdate 修改面板端口 / 访问路径（需重启生效）。
func (s *Server) handleSystemUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Listen   *string `json:"listen"`
		BasePath *string `json:"basePath"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	oldListen, oldBase := s.effectiveListen(), s.effectiveBasePath()
	changed := false
	if req.Listen != nil {
		v := strings.TrimSpace(*req.Listen)
		if port, err := strconv.Atoi(v); err == nil && port >= 1 && port <= 65535 {
			v = ":" + strconv.Itoa(port)
		}
		if !validListen(v) {
			writeErr(w, http.StatusBadRequest, "面板端口不正确，请输入 1-65535")
			return
		}
		if _, port, err := net.SplitHostPort(v); err == nil {
			if p, err := strconv.Atoi(port); err == nil && p == s.readSubSettings().Port {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("面板端口不能与订阅端口 %d 相同", p))
				return
			}
		}
		if err := s.ctl.Store.SetSetting("panel_listen", v); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		changed = changed || v != oldListen
		if v != oldListen {
			// 新面板端口先放行，重启后才不会被防火墙挡在外面
			if _, port, err := net.SplitHostPort(v); err == nil {
				if p, err := strconv.Atoi(port); err == nil && s.ctl.FirewallAuto() {
					if kind, _, err := system.OpenPort(sysCtx(r), p, "tcp"); err != nil {
						s.log.Warn("放行新面板端口失败", "port", p, "firewall", kind, "err", err)
					}
				}
			}
		}
	}
	if req.BasePath != nil {
		if !config.ValidBasePath(*req.BasePath) {
			writeErr(w, http.StatusBadRequest, "访问路径只能由字母、数字和 . _ - ~ 组成，用 / 分段（如 /panel）")
			return
		}
		v := config.NormalizeBasePath(*req.BasePath)
		if err := s.ctl.Store.SetSetting("base_path", v); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		changed = changed || v != oldBase
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"listen":      s.effectiveListen(),
		"basePath":    s.effectiveBasePath(),
		"needRestart": changed,
	})
}

func validListen(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t/?") {
		return false
	}
	i := strings.LastIndex(v, ":")
	if i < 0 {
		return false
	}
	port, err := strconv.Atoi(v[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	host := v[:i]
	if host == "" || host == "0.0.0.0" {
		return true
	}
	return strings.Count(host, ".") == 3 || host == "localhost" || strings.Contains(host, ":")
}

// handleSystemRestart 重启面板进程（先返回响应，再执行重启）。
func (s *Server) handleSystemRestart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "msg": "面板正在重启"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	s.restartMu.Lock()
	fn := s.restartFn
	s.restartMu.Unlock()
	if fn == nil {
		s.log.Warn("未配置重启回调，跳过重启")
		return
	}
	go func() {
		time.Sleep(600 * time.Millisecond)
		fn()
	}()
}

// SetTimeGuard 注入时间同步守护（可为 nil）。
func (s *Server) SetTimeGuard(g *system.TimeGuard) { s.timeGuard = g }

// timeState 返回时钟综合状态（无守护时按主机指标兜底）。
func (s *Server) timeState() string {
	if s.timeGuard != nil {
		return s.timeGuard.State()
	}
	if s.ctl.Alerts != nil {
		if met, _ := s.ctl.Alerts.Metrics(); met.ClockSynced != nil {
			if *met.ClockSynced {
				return "synced"
			}
			return "unsynced"
		}
	}
	return "unknown"
}

// timeAutofix 读取"自动校时"设置（默认开启）。
func (s *Server) timeAutofix() bool {
	if v, ok := s.ctl.Store.GetSetting("time_autofix"); ok {
		return v != "false"
	}
	return true
}

// handleSystemTime 返回时间同步状态与相关设置。
func (s *Server) handleSystemTime(w http.ResponseWriter, r *http.Request) {
	var st system.TimeStatus
	if s.timeGuard != nil {
		// 用守护每分钟刷新的缓存：这个接口被系统页每 5 秒轮询一次，不能每次都去跑 systemctl / timedatectl
		st = s.timeGuard.Status()
		st.Now = time.Now().Unix()
	} else {
		st = system.ReadTimeStatus()
		st.State = s.timeState()
	}
	tz, _ := s.ctl.Store.GetSetting("server_timezone")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         st,
		"autofix":        s.timeAutofix(),
		"serverTimezone": tz,
	})
}

// handleSystemTimeSync 立即执行一次校时：启用/安装 NTP → 等待校准 → HTTP 兜底。
func (s *Server) handleSystemTimeSync(w http.ResponseWriter, r *http.Request) {
	if s.timeGuard == nil {
		writeErr(w, http.StatusServiceUnavailable, "时间同步守护未启用")
		return
	}
	// 不绑定请求 ctx：浏览器中途断开也要把校时做完
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	detail, err := s.timeGuard.FixNow(ctx)
	if s.ctl.Alerts != nil {
		s.ctl.Alerts.RefreshMetrics()
	}
	if err != nil {
		code := http.StatusInternalServerError
		if err == system.ErrTimeFixBusy {
			code = http.StatusConflict
		}
		writeErr(w, code, err.Error()+"\n"+detail)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "detail": detail, "status": s.timeGuard.Status()})
}

// ---------- 通知（Telegram） ----------

func (s *Server) notifyManager() *alerts.Manager { return s.ctl.Alerts }

func (s *Server) handleNotifyGet(w http.ResponseWriter, r *http.Request) {
	cfg := notify.Config{}
	if m := s.notifyManager(); m != nil {
		cfg = m.Notify.Snapshot()
	}
	events := map[string]bool{}
	if cfg.Events != nil {
		events = cfg.Events
	}
	th := []int{80, 95}
	cpu, mem, disk := 90.0, 90.0, 90.0
	if m := s.notifyManager(); m != nil {
		th = m.TrafficThresholds
		cpu, mem, disk = m.CPUThreshold, m.MemThreshold, m.DiskThreshold
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":           cfg.Enabled,
		"token":             alerts.MaskToken(cfg.Token),
		"hasToken":          cfg.Token != "",
		"chatId":            cfg.ChatID,
		"apiBase":           cfg.APIBase,
		"cooldown":          cfg.Cooldown,
		"events":            events,
		"allEvents":         notify.AllEvents(),
		"trafficThresholds": th,
		"cpu":               cpu,
		"mem":               mem,
		"disk":              disk,
	})
}

func (s *Server) handleNotifyPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled           *bool           `json:"enabled"`
		Token             *string         `json:"token"`
		ChatID            *string         `json:"chatId"`
		APIBase           *string         `json:"apiBase"`
		Cooldown          *int            `json:"cooldown"`
		Events            map[string]bool `json:"events"`
		TrafficThresholds []int           `json:"trafficThresholds"`
		CPU               *float64        `json:"cpu"`
		Mem               *float64        `json:"mem"`
		Disk              *float64        `json:"disk"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	set := func(k, v string) {
		_ = s.ctl.Store.SetSetting(k, v)
	}
	if req.Enabled != nil {
		set("notify_enabled", strconv.FormatBool(*req.Enabled))
	}
	if req.Token != nil {
		t := strings.TrimSpace(*req.Token)
		// 掩码值表示不修改
		if !strings.Contains(t, "****") {
			set("notify_token", t)
		}
	}
	if req.ChatID != nil {
		set("notify_chat_id", strings.TrimSpace(*req.ChatID))
	}
	if req.APIBase != nil {
		v := strings.TrimSpace(*req.APIBase)
		if v == "" {
			v = "https://api.telegram.org"
		}
		set("notify_api_base", v)
	}
	if req.Cooldown != nil && *req.Cooldown >= 0 {
		set("notify_cooldown", strconv.Itoa(*req.Cooldown))
	}
	if req.Events != nil {
		if b, err := json.Marshal(req.Events); err == nil {
			set("notify_events", string(b))
		}
	}
	if len(req.TrafficThresholds) > 0 {
		v := sanitizeThresholds(req.TrafficThresholds)
		if b, err := json.Marshal(v); err == nil {
			set("alert_traffic_thresholds", string(b))
		}
	}
	if req.CPU != nil {
		set("alert_cpu", strconv.FormatFloat(clampPct(*req.CPU), 'f', 1, 64))
	}
	if req.Mem != nil {
		set("alert_mem", strconv.FormatFloat(clampPct(*req.Mem), 'f', 1, 64))
	}
	if req.Disk != nil {
		set("alert_disk", strconv.FormatFloat(clampPct(*req.Disk), 'f', 1, 64))
	}
	if m := s.notifyManager(); m != nil {
		m.Reload()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	m := s.notifyManager()
	if m == nil {
		writeErr(w, http.StatusInternalServerError, "通知模块未初始化")
		return
	}
	m.Reload()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := m.Notify.Test(ctx); err != nil {
		writeErr(w, http.StatusBadRequest, "发送失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func sanitizeThresholds(in []int) []int {
	out := []int{}
	seen := map[int]bool{}
	for _, v := range in {
		if v <= 0 || v >= 100 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		out = []int{80, 95}
	}
	// 简单排序
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// SystemdAvailable 判断是否由 systemd 托管。
func SystemdAvailable(unit string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "cat", unit).Run() == nil
}
