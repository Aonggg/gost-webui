package system

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 节点端口自动放行。安装脚本只放行面板端口；节点端口由面板在创建/启用时放行、删除/停用时收回，
// 否则"节点建好了但用不了"几乎总是防火墙没开。
//
// 检测顺序：ufw（active）→ firewalld（running）→ iptables（INPUT 默认 DROP/REJECT 时补 ACCEPT）→ 无。

// FirewallKind 本机防火墙类型。
type FirewallKind string

const (
	FirewallUFW       FirewallKind = "ufw"
	FirewallFirewalld FirewallKind = "firewalld"
	FirewallIptables  FirewallKind = "iptables"
	FirewallNone      FirewallKind = "none"
)

var fwCache struct {
	sync.Mutex
	kind FirewallKind
	at   time.Time
}

// DetectFirewall 识别本机在用的防火墙（结果缓存 5 分钟）。
func DetectFirewall(ctx context.Context) FirewallKind {
	fwCache.Lock()
	defer fwCache.Unlock()
	if fwCache.kind != "" && time.Since(fwCache.at) < 5*time.Minute {
		return fwCache.kind
	}
	fwCache.kind, fwCache.at = detectFirewall(ctx), time.Now()
	return fwCache.kind
}

func detectFirewall(ctx context.Context) FirewallKind {
	if hasCmd("ufw") {
		if out, err := run(ctx, "ufw", "status"); err == nil && strings.Contains(strings.ToLower(out), "status: active") {
			return FirewallUFW
		}
	}
	if hasCmd("firewall-cmd") {
		if out, err := run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(out) == "running" {
			return FirewallFirewalld
		}
	}
	if hasCmd("iptables") {
		if out, err := run(ctx, "iptables", "-S", "INPUT"); err == nil {
			// 默认策略 DROP/REJECT，或链里有 DROP/REJECT 规则：需要显式放行
			if strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT") ||
				strings.Contains(out, "-j DROP") || strings.Contains(out, "-j REJECT") {
				return FirewallIptables
			}
		}
	}
	return FirewallNone
}

// OpenPort 放行端口（proto 为 tcp / udp）。无防火墙时直接返回 FirewallNone。
// added 表示规则是这次新加的；规则早已存在（用户自己放行过）时为 false——
// 调用方据此决定是否把端口记为"面板管理"，避免之后收回时误删用户自己的规则。
func OpenPort(ctx context.Context, port int, proto string) (kind FirewallKind, added bool, err error) {
	if port <= 0 || port > 65535 {
		return FirewallNone, false, fmt.Errorf("端口无效: %d", port)
	}
	if proto != "udp" {
		proto = "tcp"
	}
	kind = DetectFirewall(ctx)
	spec := strconv.Itoa(port) + "/" + proto
	switch kind {
	case FirewallUFW:
		out, err := run(ctx, "ufw", "allow", spec)
		if err != nil {
			return kind, false, fmt.Errorf("ufw allow %s: %s", spec, out)
		}
		// ufw 对已存在规则输出 "Skipping adding existing rule"
		if strings.Contains(out, "Skipping adding existing rule") {
			return kind, false, nil
		}
	case FirewallFirewalld:
		if out, err := run(ctx, "firewall-cmd", "--permanent", "--query-port="+spec); err == nil && strings.TrimSpace(out) == "yes" {
			return kind, false, nil
		}
		if out, err := run(ctx, "firewall-cmd", "--permanent", "--add-port="+spec); err != nil {
			return kind, false, fmt.Errorf("firewall-cmd --add-port=%s: %s", spec, out)
		}
		if out, err := run(ctx, "firewall-cmd", "--reload"); err != nil {
			return kind, false, fmt.Errorf("firewall-cmd --reload: %s", out)
		}
	case FirewallIptables:
		// 带 gost-webui 注释的规则只会是面板自己加的；用户的规则没有这个注释，互不干扰
		args := []string{"INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-m", "comment", "--comment", "gost-webui", "-j", "ACCEPT"}
		if _, err := run(ctx, "iptables", append([]string{"-C"}, args...)...); err == nil {
			return kind, true, nil // 面板之前加过（如记录丢失），仍视为面板管理
		}
		if out, err := run(ctx, "iptables", append([]string{"-I"}, args...)...); err != nil {
			return kind, false, fmt.Errorf("iptables -I %s: %s", spec, out)
		}
		persistIptables(ctx)
	}
	return kind, true, nil
}

// ClosePort 收回 OpenPort 放行的端口。
func ClosePort(ctx context.Context, port int, proto string) error {
	if proto != "udp" {
		proto = "tcp"
	}
	spec := strconv.Itoa(port) + "/" + proto
	switch DetectFirewall(ctx) {
	case FirewallUFW:
		if out, err := run(ctx, "ufw", "delete", "allow", spec); err != nil && !strings.Contains(out, "Could not delete non-existent rule") {
			return fmt.Errorf("ufw delete allow %s: %s", spec, out)
		}
	case FirewallFirewalld:
		_, _ = run(ctx, "firewall-cmd", "--permanent", "--remove-port="+spec)
		_, _ = run(ctx, "firewall-cmd", "--reload")
	case FirewallIptables:
		args := []string{"INPUT", "-p", proto, "--dport", strconv.Itoa(port), "-m", "comment", "--comment", "gost-webui", "-j", "ACCEPT"}
		for {
			if _, err := run(ctx, "iptables", append([]string{"-D"}, args...)...); err != nil {
				break
			}
		}
		persistIptables(ctx)
	}
	return nil
}

// persistIptables 尽力把 iptables 规则持久化（有什么用什么，失败无妨）。
func persistIptables(ctx context.Context) {
	if hasCmd("netfilter-persistent") {
		_, _ = run(ctx, "netfilter-persistent", "save")
		return
	}
	if hasCmd("iptables-save") {
		if st, err := os.Stat("/etc/iptables"); err == nil && st.IsDir() {
			if out, err := run(ctx, "iptables-save"); err == nil {
				_ = os.WriteFile("/etc/iptables/rules.v4", []byte(out+"\n"), 0o600)
			}
		}
	}
}
