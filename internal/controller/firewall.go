package controller

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gost-webui/internal/store"
	"gost-webui/internal/system"
)

// 节点端口防火墙放行：期望集合 = 所有在服务节点的监听端口（UDP 节点加 udp）+ ExtraPorts（订阅监听等），
// 与面板自己放行过的集合（持久化在设置 fw_managed）做差：新端口放行、不再需要的收回。
// 只收回自己放行过的，不碰用户/安装脚本加的规则。

const fwManagedKey = "fw_managed"

var fwMu sync.Mutex

// FirewallAuto 返回"自动放行节点端口"开关（默认开）。
func (c *Controller) FirewallAuto() bool {
	if v, ok := c.Store.GetSetting("fw_autoopen"); ok {
		return v != "false"
	}
	return true
}

// ManagedPorts 返回面板当前放行着的端口（如 "19341/tcp"），已排序。
func (c *Controller) ManagedPorts() []string {
	m := c.loadManaged()
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		pi, _ := strconv.Atoi(strings.SplitN(out[i], "/", 2)[0])
		pj, _ := strconv.Atoi(strings.SplitN(out[j], "/", 2)[0])
		if pi != pj {
			return pi < pj
		}
		return out[i] < out[j]
	})
	return out
}

// ReleaseManagedPorts 收回 st 中记录的全部面板放行端口并清空记录。
// 供卸载流程在面板停止后调用（`gost-webui -fw-release`），返回成功收回的端口。
func ReleaseManagedPorts(ctx context.Context, st *store.Store) []string {
	fwMu.Lock()
	defer fwMu.Unlock()
	c := &Controller{Store: st}
	managed := c.loadManaged()
	released := make([]string, 0, len(managed))
	for spec := range managed {
		port, proto := splitSpec(spec)
		if err := system.ClosePort(ctx, port, proto); err != nil {
			continue
		}
		released = append(released, spec)
		delete(managed, spec)
	}
	sort.Strings(released)
	c.saveManaged(managed)
	return released
}

func (c *Controller) loadManaged() map[string]bool {
	m := map[string]bool{}
	if v, ok := c.Store.GetSetting(fwManagedKey); ok && v != "" {
		var list []string
		if json.Unmarshal([]byte(v), &list) == nil {
			for _, k := range list {
				m[k] = true
			}
		}
	}
	return m
}

func (c *Controller) saveManaged(m map[string]bool) {
	list := make([]string, 0, len(m))
	for k := range m {
		list = append(list, k)
	}
	sort.Strings(list)
	b, _ := json.Marshal(list)
	_ = c.Store.SetSetting(fwManagedKey, string(b))
}

// SyncFirewall 按当前节点状态放行/收回端口。关闭自动放行时收回自己放行过的端口后不再管理。
func (c *Controller) SyncFirewall(ctx context.Context) {
	fwMu.Lock()
	defer fwMu.Unlock()

	want := map[string]bool{}
	if c.FirewallAuto() {
		for _, n := range c.Nodes() {
			if !n.Serving() || n.ListenPort <= 0 {
				continue
			}
			want[strconv.Itoa(n.ListenPort)+"/tcp"] = true
			if n.UDP && !n.IsReality() {
				want[strconv.Itoa(n.ListenPort)+"/udp"] = true
			}
		}
		if c.ExtraPorts != nil {
			for _, p := range c.ExtraPorts() {
				if p > 0 {
					want[strconv.Itoa(p)+"/tcp"] = true
				}
			}
		}
	}

	managed := c.loadManaged()
	changed := false
	for spec := range want {
		if managed[spec] {
			continue
		}
		port, proto := splitSpec(spec)
		kind, added, err := system.OpenPort(ctx, port, proto)
		if err != nil {
			c.Log.Warn("放行端口失败", "port", spec, "firewall", kind, "err", err)
			continue
		}
		if kind == system.FirewallNone {
			continue // 没有防火墙：无需记录，也没有可收回的规则
		}
		if !added {
			c.Log.Info("端口已由用户自行放行，面板不接管", "port", spec, "firewall", kind)
			continue
		}
		c.Log.Info("已放行节点端口", "port", spec, "firewall", kind)
		managed[spec] = true
		changed = true
	}
	for spec := range managed {
		if want[spec] {
			continue
		}
		port, proto := splitSpec(spec)
		if err := system.ClosePort(ctx, port, proto); err != nil {
			c.Log.Warn("收回端口失败", "port", spec, "err", err)
			continue
		}
		c.Log.Info("已收回节点端口", "port", spec)
		delete(managed, spec)
		changed = true
	}
	if changed {
		c.saveManaged(managed)
	}
}

func splitSpec(spec string) (int, string) {
	parts := strings.SplitN(spec, "/", 2)
	port, _ := strconv.Atoi(parts[0])
	proto := "tcp"
	if len(parts) == 2 {
		proto = parts[1]
	}
	return port, proto
}
