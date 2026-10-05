package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"gost-webui/internal/cert"
	"gost-webui/internal/gostmgr"
)

// handleQRText 生成任意文本（通常是订阅链接）的二维码 PNG，供已登录前端展示。
func (s *Server) handleQRText(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if strings.TrimSpace(text) == "" {
		writeErr(w, http.StatusBadRequest, "缺少 text 参数")
		return
	}
	png, err := qrcode.Encode(text, qrcode.Medium, 320)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// isClashUA 判断客户端 User-Agent 是否属于 Clash 系（需要 YAML 配置）。
func isClashUA(ua string) bool {
	ua = strings.ToLower(ua)
	return strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "stash")
}

// handleNodeSubscription 返回指定节点的专属订阅信息：链接、Clash/通用地址与二维码所需 URL。
func (s *Server) handleNodeSubscription(w http.ResponseWriter, r *http.Request) {
	node := s.ctl.Node(r.PathValue("id"))
	if node == nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	// 旧节点可能没有令牌，首次查看时补齐并持久化。
	if strings.TrimSpace(node.SubToken) == "" {
		node.SubToken = randomPassword(24)
		if err := s.ctl.Store.SaveNode(node); err != nil {
			writeErr(w, http.StatusInternalServerError, "保存令牌失败: "+err.Error())
			return
		}
		_, _ = s.ctl.LoadNodes()
	}
	set := s.readSubSettings()
	scheme, host := "http", s.publicHost()
	if s.subUseTLS() {
		scheme, host = "https", set.Domain
	}
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	base := s.subBaseURL()
	token := node.SubToken
	// Clash 能表达的 gost 本机节点：标准 ss / http / socks5 直接走 TCP（叠加 ws/tls 等通道的组合 Clash 无对应类型）
	gp, gt := gostmgr.NodeGostProtocol(node), gostmgr.NodeGostTransport(node)
	clashSupported := node.Mode != "gost" || (gt == "tcp" && (gp == "ss" || gp == "http" || gp == "socks5"))
	writeJSON(w, http.StatusOK, map[string]any{
		"url":            base + "/" + token,
		"clashURL":       base + "/" + token + "/clash",
		"universalURL":   base + "/" + token + "/universal",
		"token":          token,
		"scheme":         scheme,
		"host":           host,
		"port":           set.Port,
		"suffix":         set.Suffix,
		"certReady":      s.certReady(),
		"enabled":        node.Enabled,
		"expired":        node.Expired(),
		"nodeName":       node.Name,
		"clashSupported": clashSupported,
	})
}

// handleNodeSubscriptionReset 重新生成指定节点的订阅令牌（旧链接与二维码立即失效）。
func (s *Server) handleNodeSubscriptionReset(w http.ResponseWriter, r *http.Request) {
	node := s.ctl.Node(r.PathValue("id"))
	if node == nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	node.SubToken = randomPassword(24)
	if err := s.ctl.Store.SaveNode(node); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	_, _ = s.ctl.LoadNodes()
	writeJSON(w, http.StatusOK, map[string]any{"token": node.SubToken})
}

// subConfigView 汇总「订阅与证书」配置，供 GET/PUT 复用。
func (s *Server) subConfigView(ctx context.Context) map[string]any {
	set := s.readSubSettings()
	var st cert.Status
	if prov := s.certProvider(); prov != nil {
		st = prov.Status(ctx)
	}
	hasManual := strings.TrimSpace(set.CertPEM) != "" && strings.TrimSpace(set.KeyPEM) != ""
	// 证书/私钥内容用于前端「证书与私钥」只读展示：手动优先回显存储值，
	// ACME 则从缓存读取。这些内容仅在需登录的面板接口下返回，不出面板。
	certPEM, keyPEM, certSource := "", "", ""
	if hasManual {
		certPEM, keyPEM, certSource = set.CertPEM, set.KeyPEM, "manual"
	} else if prov := s.certProvider(); prov != nil {
		certPEM, keyPEM, certSource = prov.Content(ctx)
	}
	var listenErr string
	if err := s.SubError(); err != nil {
		listenErr = err.Error()
	}
	return map[string]any{
		"port":          set.Port,
		"suffix":        set.Suffix,
		"domain":        set.Domain,
		"email":         set.Email,
		"cert":          st,
		"sampleURL":     s.subBaseURL() + "/<节点令牌>",
		"hasManualCert": hasManual,
		"tls":           s.subUseTLS(),
		"certPEM":       certPEM,
		"keyPEM":        keyPEM,
		"certSource":    certSource,
		// listening / listenError：订阅监听器实际状态；端口被占用时前端据此提示，而不是只在日志里留一行 WARN。
		"listening":   listenErr == "",
		"listenError": listenErr,
	}
}

// handleSubConfigGet 返回订阅与证书配置。
func (s *Server) handleSubConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.subConfigView(r.Context()))
}

// handleSubConfigPut 校验并保存订阅与证书配置，保存后热重启订阅监听器。
func (s *Server) handleSubConfigPut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port    *int    `json:"port"`
		Suffix  *string `json:"suffix"`
		Domain  *string `json:"domain"`
		Email   *string `json:"email"`
		TLSCert *string `json:"tlsCert"`
		TLSKey  *string `json:"tlsKey"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	st := s.ctl.Store
	if req.Port != nil {
		if *req.Port < 1 || *req.Port > 65535 {
			writeErr(w, http.StatusBadRequest, "订阅端口无效（1-65535）")
			return
		}
		if *req.Port == s.panelPort() {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("订阅端口不能与面板端口 %d 相同", *req.Port))
			return
		}
		if err := st.SetSetting("sub_port", strconv.Itoa(*req.Port)); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.Suffix != nil {
		sfx, ok := normalizeSubSuffix(*req.Suffix)
		if !ok {
			writeErr(w, http.StatusBadRequest, "订阅路径只能由字母、数字和 . _ - ~ 组成，用 / 分段（如 /sub）")
			return
		}
		if err := st.SetSetting("sub_suffix", sfx); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.Domain != nil {
		d := strings.ToLower(strings.TrimSpace(*req.Domain))
		if d != "" && !validHostname(d) {
			writeErr(w, http.StatusBadRequest, "订阅域名格式不正确")
			return
		}
		if err := st.SetSetting("sub_domain", d); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.Email != nil {
		e := strings.TrimSpace(*req.Email)
		if e != "" && !strings.Contains(e, "@") {
			writeErr(w, http.StatusBadRequest, "ACME 邮箱格式不正确")
			return
		}
		if err := st.SetSetting("sub_acme_email", e); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.TLSCert != nil {
		if err := st.SetSetting("sub_tls_cert", strings.TrimSpace(*req.TLSCert)); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.TLSKey != nil {
		if err := st.SetSetting("sub_tls_key", strings.TrimSpace(*req.TLSKey)); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	// 热生效：重建订阅监听器（无需重启面板），并同步防火墙放行订阅端口。
	// 监听失败（端口被占用）时设置已保存，但要把失败原因直接告诉用户。
	listenErr := s.RestartSubscription()
	s.ctl.SyncFirewall(sysCtx(r))
	if listenErr != nil {
		writeErr(w, http.StatusConflict, listenErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.subConfigView(r.Context()))
}

// handleCertIssue 立即为配置的域名申请/续期证书（需 domain+email）。
func (s *Server) handleCertIssue(w http.ResponseWriter, r *http.Request) {
	prov := s.certProvider()
	if prov == nil {
		writeErr(w, http.StatusInternalServerError, "证书模块未初始化")
		return
	}
	set := s.readSubSettings()
	if set.Domain == "" || set.Email == "" {
		writeErr(w, http.StatusBadRequest, "请先填写订阅域名与 ACME 邮箱并保存")
		return
	}
	// 同步最新配置并重启 :80 挑战监听，稍候待其就绪。
	if err := prov.Reload(set.Domain, set.Email, set.CertPEM, set.KeyPEM); err != nil {
		writeErr(w, http.StatusBadRequest, "证书配置无效: "+err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	st, err := prov.IssueNow(ctx)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "证书申请失败: "+err.Error())
		return
	}
	// 证书就绪后重启订阅监听器以切换到 HTTPS。
	s.RestartSubscription()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert": st, "config": s.subConfigView(r.Context())})
}
