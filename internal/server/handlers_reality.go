package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"gost-webui/internal/model"
	"gost-webui/internal/singbox"
)

// handleRealityCredential 为 reality 节点生成服务端凭据（密钥对/UUID/ShortID）。
func (s *Server) handleRealityCredential(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := singbox.GenerateRealityKeypair()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "生成密钥对失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uuid":    singbox.GenerateUUID(),
		"privKey": priv,
		"pubKey":  pub,
		"shortId": singbox.GenerateShortID(),
	})
}

// handleRealityAvailable 报告 sing-box 引擎状态（前端据此决定是否展示 reality 选项）。
func (s *Server) handleRealityAvailable(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"available": s.ctl.RealityAvailable()})
}

// handleRealitySNI 随机挑选一个本机可达的伪装域名（供表单「随机」按钮）。
func (s *Server) handleRealitySNI(w http.ResponseWriter, r *http.Request) {
	sni, probes, err := singbox.PickRealitySNI(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sni": sni, "probes": probes})
}

// buildRealityNode 处理 sing-box 承载的 VLESS 节点：默认 REALITY；
// 「加速兼容模式」改为 VLESS + WebSocket（源站自签 TLS 或明文），可被 CDN / HTTP 类加速按 HTTP 回源转发。
func (s *Server) buildRealityNode(in *nodeInput, old *model.Node) (*model.Node, error) {
	if !s.ctl.RealityAvailable() {
		return nil, fmt.Errorf("本机未安装 sing-box，无法创建 REALITY 节点（安装后重试）")
	}
	n := newNodeBase(old)
	n.Mode = "reality"
	n.GostLocal = true // 复用"本机落地"语义：监听端口即服务端口
	n.UDP = false

	switch strings.ToLower(strings.TrimSpace(in.RealityTransport)) {
	case "", "reality":
		n.RealityTransport = ""
		n.Protocol = "VLESS+REALITY"
	case "vmess":
		n.RealityTransport = "vmess"
		n.Protocol = "VMess+TCP"
	case "ws-tls":
		n.RealityTransport = "ws-tls"
		n.Protocol = "VLESS+WS+TLS"
	case "ws":
		n.RealityTransport = "ws"
		n.Protocol = "VLESS+WS"
	default:
		return nil, fmt.Errorf("传输方式无效（reality / vmess / ws-tls / ws）")
	}
	// 加速兼容模式（vmess / ws / ws-tls）：不需要伪装域名、密钥对、ShortID
	isWS := n.RealityTransport != ""

	n.RealityUUID = strings.TrimSpace(in.RealityUuid)
	n.RealityPriv = strings.TrimSpace(in.RealityPriv)
	n.RealityPub = strings.TrimSpace(in.RealityPub)
	n.RealityShortID = strings.ToLower(strings.TrimSpace(in.RealityShortId))
	n.RealitySNI = strings.ToLower(strings.TrimSpace(in.RealitySni))

	// 编辑保留：私钥列表接口不下发，提交为空时沿用旧值
	if old != nil && old.IsReality() {
		if n.RealityPriv == "" {
			n.RealityPriv = old.RealityPriv
		}
		if n.RealityUUID == "" {
			n.RealityUUID = old.RealityUUID
		}
		if n.RealityShortID == "" {
			n.RealityShortID = old.RealityShortID
		}
		if n.RealityPub == "" {
			n.RealityPub = old.RealityPub
		}
		if n.RealitySNI == "" && !isWS {
			n.RealitySNI = old.RealitySNI
		}
		n.RealityWSPath = old.RealityWSPath
	}
	if n.RealityUUID == "" {
		if isWS {
			n.RealityUUID = singbox.GenerateUUID() // WS 模式只需 UUID，直接生成
		} else {
			return nil, fmt.Errorf("缺少 UUID，请点击生成")
		}
	}

	if isWS {
		// 加速兼容模式：不需要伪装域名/密钥对/ShortID；WS 路径留空自动生成（vmess 不用路径）
		if p := strings.TrimSpace(in.RealityWsPath); p != "" {
			if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " ?#") {
				return nil, fmt.Errorf("WebSocket 路径无效（以 / 开头，不含空格、?、#）")
			}
			n.RealityWSPath = p
		}
		if n.RealityWSPath == "" {
			n.RealityWSPath = singbox.GenerateWSPath()
		}
	} else {
		if n.RealitySNI == "" {
			// 留空：从候选池挑一个本机可达、支持 TLS 1.3 + H2 的大型站点
			sni, _, err := singbox.PickRealitySNI(context.Background())
			if err != nil {
				return nil, err
			}
			n.RealitySNI = sni
		}
		if !singbox.ValidServerName(n.RealitySNI) {
			return nil, fmt.Errorf("伪装域名无效（应为 www.example.com 形式）")
		}
		switch {
		case n.RealityPriv == "" || n.RealityPub == "":
			return nil, fmt.Errorf("缺少 REALITY 密钥对，请点击生成")
		case n.RealityShortID == "":
			return nil, fmt.Errorf("缺少 ShortID，请点击生成")
		}
	}

	// 加速入口（可选）：host:port，填了就按它生成客户端链接
	n.AccelHost = ""
	if in.AccelHost != nil {
		if a := strings.TrimSpace(*in.AccelHost); a != "" {
			h, p, err := net.SplitHostPort(a)
			if err != nil || (net.ParseIP(h) == nil && !validHostname(h)) {
				return nil, fmt.Errorf("加速入口格式应为 域名或IP:端口，如 a.example.com:30189")
			}
			if port, err := strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("加速入口端口无效")
			}
			n.AccelHost = net.JoinHostPort(h, p)
		}
	} else if old != nil {
		n.AccelHost = old.AccelHost
	}

	n.Name = strings.TrimSpace(in.Name)
	if n.Name == "" {
		if isWS {
			n.Name = n.Protocol
		} else {
			n.Name = "REALITY-" + n.RealitySNI
		}
	}
	n.TargetHost = ""
	n.TargetPort = 0
	if err := s.applyCommon(n, in, old, false); err != nil {
		return nil, err
	}
	up, err := upstreamFrom(in.Upstream, old)
	if err != nil {
		return nil, err
	}
	n.Upstream = up
	return n, nil
}
