// Package singbox 以"每节点一个 sing-box 进程"的方式承载 VLESS+REALITY 节点：
// 每个实例拥有独立配置目录与 clash API 端口，进程级 dlTotal/upTotal 即节点精确
// 流量，配额暂停=停进程，节点间互不影响。与 gost 引擎并存。
package singbox

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gost-webui/internal/model"
)

// ---------- 凭据 ----------

// RealityCred 是 sing-box 节点的凭据与传输方式（存于 model.Node）。
// Transport 为空/"reality" 时用 REALITY（ServerName/PrivateKey/PublicKey/ShortID 生效）；
// "ws-tls" / "ws" 为加速兼容模式：VLESS over WebSocket（WSPath），源站自签 TLS 或明文。
type RealityCred struct {
	UUID       string `json:"uuid"`
	PrivateKey string `json:"privKey"`
	PublicKey  string `json:"pubKey"`
	ShortID    string `json:"shortId"`
	ServerName string `json:"serverName"`
	Transport  string `json:"transport,omitempty"`
	WSPath     string `json:"wsPath,omitempty"`
}

// IsWS 判断是否为 WebSocket 加速兼容模式。
func (c *RealityCred) IsWS() bool { return c.Transport == "ws" || c.Transport == "ws-tls" }

// GenerateWSPath 生成随机 WebSocket 路径（/ + 12 位 hex）。
func GenerateWSPath() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "/" + hex.EncodeToString(b)
}

func GenerateRealityKeypair() (priv, pub string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	priv = base64.RawURLEncoding.EncodeToString(key.Bytes())
	pub = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	return priv, pub, nil
}

func GenerateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func GenerateShortID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func ValidServerName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t:/@") {
		return false
	}
	return true
}

// ClientURL 生成客户端直连本机的分享链接（host 为面板公网地址）。
// REALITY：vless+reality；VMess+TCP：vmess://（v2rayN JSON）；WS+TLS：源站自签证书，带 allowInsecure=1；WS 明文：security=none。
func ClientURL(c *RealityCred, port int, host, name string) string {
	switch c.Transport {
	case "vmess":
		return vmessURL(c.UUID, host, port, name)
	case "ws-tls":
		return fmt.Sprintf(
			"vless://%s@%s:%d?encryption=none&security=tls&sni=%s&allowInsecure=1&type=ws&host=%s&path=%s#%s",
			c.UUID, host, port, host, host, urlEscape(c.WSPath), urlEscape(name))
	case "ws":
		return fmt.Sprintf(
			"vless://%s@%s:%d?encryption=none&security=none&type=ws&host=%s&path=%s#%s",
			c.UUID, host, port, host, urlEscape(c.WSPath), urlEscape(name))
	}
	return fmt.Sprintf(
		"vless://%s@%s:%d?encryption=none&security=reality&type=tcp&sni=%s&fp=chrome&pbk=%s&sid=%s&flow=xtls-rprx-vision#%s",
		c.UUID, host, port, c.ServerName, c.PublicKey, c.ShortID, urlEscape(name))
}

// vmessURL 生成 v2rayN 约定的 vmess:// 链接（base64 JSON，v2rayN / v2rayNG / 小火箭 / Clash 均可导入）：
// VMess + TCP、无 TLS、alterId 0、加密 auto。
func vmessURL(uuid, host string, port int, name string) string {
	obj := map[string]any{
		"v": "2", "ps": name, "add": host, "port": strconv.Itoa(port), "id": uuid,
		"aid": "0", "scy": "auto", "net": "tcp", "type": "none", "host": "", "path": "", "tls": "",
	}
	b, _ := json.Marshal(obj)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// AccelClientURL 生成"经加速入口"的客户端链接。accel 为入口 host:port。
// WS 模式：加速入口（CDN/HTTP 加速）对客户端提供正式 TLS，SNI/Host 用入口域名；
// REALITY：纯 TCP 中转，只换地址端口。
func AccelClientURL(c *RealityCred, accel, name string) string {
	host, portStr, err := net.SplitHostPort(accel)
	if err != nil {
		return ""
	}
	port, _ := strconv.Atoi(portStr)
	if c.Transport == "vmess" {
		return vmessURL(c.UUID, host, port, name)
	}
	if c.IsWS() {
		return fmt.Sprintf(
			"vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%s#%s",
			c.UUID, host, port, host, host, urlEscape(c.WSPath), urlEscape(name))
	}
	return ClientURL(c, port, host, name)
}

// CredOf 从节点取出 sing-box 凭据与传输方式。
func CredOf(n *model.Node) *RealityCred {
	return &RealityCred{
		UUID: n.RealityUUID, PrivateKey: n.RealityPriv, PublicKey: n.RealityPub,
		ShortID: n.RealityShortID, ServerName: n.RealitySNI,
		Transport: n.SBTransport(), WSPath: n.RealityWSPath,
	}
}

// NodeClientURL 生成节点的客户端链接：填了加速入口就指向入口，否则直连面板主机。
func NodeClientURL(n *model.Node, host string) string {
	c := CredOf(n)
	if n.AccelHost != "" {
		if u := AccelClientURL(c, n.AccelHost, n.Name); u != "" {
			return u
		}
	}
	return ClientURL(c, n.ListenPort, host, n.Name)
}

func urlEscape(s string) string {
	const hd = "0123456789ABCDEF"
	var b []byte
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b = append(b, c)
			continue
		}
		b = append(b, '%', hd[c>>4], hd[c&0xf])
	}
	return string(b)
}

// ---------- sing-box 配置 ----------

type instanceConfig struct {
	Log struct {
		Level     string `json:"level"`
		Timestamp bool   `json:"timestamp"`
	} `json:"log"`
	Inbounds  []json.RawMessage `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Route     struct {
		Final string `json:"final"`
	} `json:"route"`
	Experimental struct {
		ClashAPI struct {
			ExternalController string `json:"external_controller"`
			Secret             string `json:"secret,omitempty"`
		} `json:"clash_api"`
	} `json:"experimental"`
}

// buildInstanceConfig 生成单节点 config.json；up 非空时出站经落地机的 SOCKS5 / HTTP 代理；
// certFile/keyFile 仅 ws-tls 模式使用。apiSecret 保护 clash API：本机其它用户/进程不能读连接明细或改配置。
func buildInstanceConfig(id string, port int, c *RealityCred, apiAddr, apiSecret string, up *model.Upstream, certFile, keyFile string) ([]byte, error) {
	ic := instanceConfig{}
	ic.Log.Level = "warning"
	ic.Log.Timestamp = true
	ic.Route.Final = "out"
	ic.Experimental.ClashAPI.ExternalController = apiAddr
	ic.Experimental.ClashAPI.Secret = apiSecret

	inbound := map[string]any{
		"type":        "vless",
		"tag":         id,
		"listen":      "::",
		"listen_port": port,
	}
	switch c.Transport {
	case "vmess":
		// VMess + TCP、无 TLS：首包为 VMess 加密头，纯 TCP 转发类加速可直接透传
		inbound["type"] = "vmess"
		inbound["users"] = []map[string]any{{"uuid": c.UUID, "alterId": 0}}
	case "ws", "ws-tls":
		// WebSocket 不能用 vision flow（flow 要求端到端 TLS 直通）
		inbound["users"] = []map[string]any{{"uuid": c.UUID}}
		inbound["transport"] = map[string]any{
			"type": "ws", "path": c.WSPath,
			"early_data_header_name": "Sec-WebSocket-Protocol", "max_early_data": 2048,
		}
		if c.Transport == "ws-tls" {
			inbound["tls"] = map[string]any{"enabled": true, "certificate_path": certFile, "key_path": keyFile}
		}
	default:
		inbound["users"] = []map[string]any{{"uuid": c.UUID, "flow": "xtls-rprx-vision"}}
		inbound["tls"] = map[string]any{
			"enabled":     true,
			"server_name": c.ServerName,
			"reality": map[string]any{
				"enabled":     true,
				"handshake":   map[string]any{"server": c.ServerName, "server_port": 443},
				"private_key": c.PrivateKey,
				"short_id":    []string{c.ShortID},
			},
		}
	}
	ib, err := json.Marshal(inbound)
	if err != nil {
		return nil, err
	}
	ob, err := json.Marshal(outboundFor(up))
	if err != nil {
		return nil, err
	}
	ic.Inbounds = []json.RawMessage{ib}
	ic.Outbounds = []json.RawMessage{ob}
	return json.MarshalIndent(&ic, "", "  ")
}

// outboundFor 生成出站：无出口代理时直出；有则 socks / http 出站（https 为 http + TLS）。
func outboundFor(up *model.Upstream) map[string]any {
	if up == nil || up.Host == "" || up.Port <= 0 {
		return map[string]any{"type": "direct", "tag": "out"}
	}
	ob := map[string]any{"tag": "out", "server": up.Host, "server_port": up.Port}
	switch up.Type {
	case "http", "https":
		ob["type"] = "http"
		if up.Type == "https" {
			ob["tls"] = map[string]any{"enabled": true, "server_name": up.Host}
		}
	default:
		ob["type"] = "socks"
		ob["version"] = "5"
	}
	if up.User != "" {
		ob["username"] = up.User
		ob["password"] = up.Pass
	}
	return ob
}

// ---------- 实例池 ----------

// Stats 是实例运行态。
type Stats struct {
	Running bool
	PID     int
	Down    uint64
	Up      uint64
	Conns   int
	Ready   bool
	LastErr string
}

type instance struct {
	id        string
	dir       string
	confFile  string
	logFile   string
	apiAddr   string
	apiSecret string
	bin       string
	log       *slog.Logger

	mu      sync.Mutex
	cmd     *exec.Cmd
	ready   bool
	lastErr string
	stop    chan struct{}
	dead    bool
}

// Pool 管理全部 reality 节点实例。
type Pool struct {
	dataDir string // 例：/var/lib/gost-webui/singbox
	bin     string
	log     *slog.Logger

	mu   sync.Mutex
	inst map[string]*instance
}

func NewPool(dataDir, bin string, log *slog.Logger) *Pool {
	return &Pool{dataDir: dataDir, bin: bin, log: log, inst: map[string]*instance{}}
}

// Installed 判断二进制可用（版本输出包含 sing-box）。
func Installed(bin string) bool {
	if bin == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	return err == nil && strings.Contains(string(out), "sing-box")
}

// apiPortFor 由节点 ID 散列到 19100-19899 的本地回环端口；与任一节点监听端口相同、
// 或已被占用（其它服务）时顺延到下一个空闲端口——否则 clash API 绑不上，sing-box 起不来。
// 实例一旦创建就沿用其端口（见 Apply），避免每次应用配置都换端口触发重启。
func apiPortFor(id string, avoid map[int]bool) int {
	var h uint32
	for _, ch := range id {
		h = h*131 + uint32(ch)
	}
	base := 19100 + int(h%800)
	for i := 0; i < 800; i++ {
		p := 19100 + (base-19100+i)%800
		if avoid[p] {
			continue
		}
		if l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			_ = l.Close()
			return p
		}
	}
	return base
}

func (p *Pool) nodeDir(id string) string { return filepath.Join(p.dataDir, id) }

// Apply 写入/更新节点配置并确保进程按期望状态运行（enabled 决定是否拉起）。
// avoidPorts 是面板所有节点的监听端口（gost 可能尚未绑定，不能只靠探测），clash API 端口须避开。
func (p *Pool) Apply(ctx context.Context, id string, port int, cred *RealityCred, up *model.Upstream, avoidPorts []int, enabled bool) error {
	dir := p.nodeDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	confFile := filepath.Join(dir, "config.json")
	p.mu.Lock()
	inst := p.inst[id]
	if inst == nil {
		avoid := map[int]bool{port: true}
		for _, ap := range avoidPorts {
			avoid[ap] = true
		}
		apiAddr := "127.0.0.1:" + strconv.Itoa(apiPortFor(id, avoid))
		inst = &instance{id: id, dir: dir, confFile: confFile, logFile: filepath.Join(dir, "sb.log"), apiAddr: apiAddr, apiSecret: GenerateUUID(), bin: p.bin, log: p.log}
		p.inst[id] = inst
	}
	apiAddr, apiSecret := inst.apiAddr, inst.apiSecret
	p.mu.Unlock()
	certFile, keyFile := "", ""
	if cred.Transport == "ws-tls" {
		var cerr error
		if certFile, keyFile, cerr = EnsureSelfSignedCert(dir, ""); cerr != nil {
			return fmt.Errorf("生成自签证书失败: %w", cerr)
		}
	}
	cfgBytes, err := buildInstanceConfig(id, port, cred, apiAddr, apiSecret, up, certFile, keyFile)
	if err != nil {
		return err
	}

	p.mu.Lock()
	changed := false
	if old, err := os.ReadFile(confFile); err != nil || string(old) != string(cfgBytes) {
		tmp := confFile + ".tmp"
		if err := os.WriteFile(tmp, cfgBytes, 0o600); err != nil {
			p.mu.Unlock()
			return err
		}
		if err := os.Rename(tmp, confFile); err != nil {
			p.mu.Unlock()
			return err
		}
		changed = true
	}
	p.mu.Unlock()

	if !enabled {
		inst.stopProcess()
		return nil
	}
	if changed || inst.isDead() {
		inst.restart(ctx)
	}
	return nil
}

// Remove 停止并删除节点实例目录。
func (p *Pool) Remove(id string) {
	p.mu.Lock()
	inst := p.inst[id]
	delete(p.inst, id)
	p.mu.Unlock()
	if inst != nil {
		inst.stopProcess()
		_ = os.RemoveAll(inst.dir)
	}
}

// StopAll 面板退出时调用。
func (p *Pool) StopAll() {
	p.mu.Lock()
	all := make([]*instance, 0, len(p.inst))
	for _, i := range p.inst {
		all = append(all, i)
	}
	p.mu.Unlock()
	for _, i := range all {
		i.stopProcess()
	}
}

// Stats 返回实例运行态；实例不存在返回零值。
func (p *Pool) Stats(ctx context.Context, id string) Stats {
	p.mu.Lock()
	inst := p.inst[id]
	p.mu.Unlock()
	if inst == nil {
		return Stats{}
	}
	return inst.stats(ctx)
}

// AnyStats 批量取回。
func (p *Pool) AnyStats(ctx context.Context, ids []string) map[string]Stats {
	out := make(map[string]Stats, len(ids))
	for _, id := range ids {
		out[id] = p.Stats(ctx, id)
	}
	return out
}

// IsRealityInstalled 暴露给 handler 判断能否添加 reality 节点。
func (p *Pool) RealityInstalled() bool { return Installed(p.bin) }

// ---------- 单实例进程 ----------

func (i *instance) isDead() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.cmd == nil || i.cmd.Process == nil
}

func (i *instance) stopProcess() {
	i.mu.Lock()
	if i.stop != nil {
		close(i.stop)
		i.stop = nil
	}
	cmd := i.cmd
	i.cmd = nil
	i.ready = false
	i.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
}

// reapOrphan 回收孤儿实例：面板异常退出（OOM/kill -9）时子进程可能存活并继续占用
// 监听端口，此时若再拉新实例会因端口占用失败退避，而旧孤儿的引擎计数与清零后的
// 内存基线错位，导致流量被整体重复累加。启动前按 pid 文件+端口双保险清掉旧进程。
func (i *instance) reapOrphan() {
	// 1) pid 文件
	pidFile := filepath.Join(i.dir, "sb.pid")
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			if proc, err := os.FindProcess(pid); err == nil && proc.Signal(syscall.Signal(0)) == nil {
				if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil &&
					strings.Contains(string(cmdline), "-D "+i.dir) {
					i.log.Warn("回收上一代孤儿 sing-box 进程", "node", i.id, "pid", pid)
					_ = proc.Signal(syscall.SIGTERM)
					for k := 0; k < 20; k++ {
						time.Sleep(200 * time.Millisecond)
						if proc.Signal(syscall.Signal(0)) != nil {
							break
						}
					}
					_ = proc.Kill()
				}
			}
		}
	}
	// 2) 端口兜底：谁占着我们的 clash API 端口就杀谁（cmdline 校验防误杀）
	if pid := pidListeningOn(i.apiAddr); pid > 0 {
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil &&
			strings.Contains(string(cmdline), "sing-box") && strings.Contains(string(cmdline), i.dir) {
			i.log.Warn("回收占用 API 端口的孤儿进程", "node", i.id, "pid", pid)
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Signal(syscall.SIGTERM)
				time.Sleep(500 * time.Millisecond)
				_ = proc.Kill()
			}
		}
	}
}

// pidListeningOn 通过 /proc/net/tcp(6) 找到监听 addr:port 的进程 pid（需要同 uid 权限，失败返回 0）
func pidListeningOn(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	hexPort := fmt.Sprintf("%04X", port)
	inodes := map[string]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			// local_address 形如 0100007F:4D9D，状态 0A=LISTEN
			if !strings.HasSuffix(fields[1], ":"+hexPort) || fields[3] != "0A" {
				continue
			}
			inodes[fields[9]] = true
		}
	}
	if len(inodes) == 0 {
		return 0
	}
	pids, _ := os.ReadDir("/proc")
	for _, pd := range pids {
		if !pd.IsDir() {
			continue
		}
		fdDir := filepath.Join("/proc", pd.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				if inodes[strings.Trim(link, "socket:[]")] {
					if pid, err := strconv.Atoi(pd.Name()); err == nil {
						return pid
					}
				}
			}
		}
	}
	return 0
}

// writePidFile 记录当前实例 pid（supervise 启动成功后调用）。
func (i *instance) writePidFile(pid int) {
	_ = os.WriteFile(filepath.Join(i.dir, "sb.pid"), []byte(strconv.Itoa(pid)), 0o600)
}

// restart 停止旧进程并重新拉起 + 守护。
func (i *instance) restart(ctx context.Context) {
	i.stopProcess()
	go i.supervise()
}

func (i *instance) supervise() {
	stop := make(chan struct{})
	i.mu.Lock()
	i.stop = stop
	i.mu.Unlock()

	backoff := time.Second
	for {
		select {
		case <-stop:
			return
		default:
		}
		i.log.Info("启动 sing-box 实例", "node", i.id, "api", i.apiAddr)
		out := newRotatingWriter(i.logFile, 4<<20)
		i.reapOrphan()
		cmd := exec.Command(i.bin, "run", "-D", i.dir, "-c", i.confFile)
		cmd.Stdout = out
		cmd.Stderr = out
		if err := cmd.Start(); err != nil {
			i.setErr(err.Error())
			i.log.Warn("sing-box 启动失败", "node", i.id, "err", err)
			select {
			case <-time.After(backoff):
			case <-stop:
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		i.mu.Lock()
		i.cmd = cmd
		i.mu.Unlock()
		i.writePidFile(cmd.Process.Pid)
		backoff = time.Second

		err := cmd.Wait()
		i.mu.Lock()
		if i.cmd == cmd {
			i.cmd = nil
			i.ready = false
		}
		i.mu.Unlock()
		if err != nil {
			i.setErr(err.Error())
		}
		select {
		case <-stop:
			return
		default:
		}
		i.log.Warn("sing-box 实例退出，准备重启", "node", i.id, "err", err)
		select {
		case <-time.After(backoff):
		case <-stop:
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (i *instance) setErr(s string) {
	i.mu.Lock()
	i.lastErr = s
	i.mu.Unlock()
}

type connectionsResp struct {
	Connections []struct {
		Download uint64 `json:"download"`
		Upload   uint64 `json:"upload"`
	} `json:"connections"`
	DownloadTotal uint64 `json:"downloadTotal"`
	UploadTotal   uint64 `json:"uploadTotal"`
}

func (i *instance) stats(ctx context.Context) Stats {
	i.mu.Lock()
	procRunning := i.cmd != nil && i.cmd.Process != nil
	pid := 0
	if procRunning {
		pid = i.cmd.Process.Pid
	}
	api, secret := i.apiAddr, i.apiSecret
	lastErr := i.lastErr
	i.mu.Unlock()

	st := Stats{PID: pid, LastErr: lastErr}
	if !procRunning {
		return st
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, "http://"+api+"/connections", nil)
	if err != nil {
		return st
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return st
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return st
	}
	var cr connectionsResp
	if err := json.Unmarshal(body, &cr); err != nil {
		return st
	}
	st.Running = true
	st.Ready = true
	st.Down = cr.DownloadTotal
	st.Up = cr.UploadTotal
	st.Conns = len(cr.Connections)
	return st
}

// ---------- 日志滚动 ----------

type rotatingWriter struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func newRotatingWriter(path string, max int64) io.Writer {
	return &rotatingWriter{path: path, max: max}
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
			return len(p), nil
		}
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return len(p), nil
		}
		st, _ := f.Stat()
		w.f = f
		if st != nil {
			w.size = st.Size()
		}
	}
	if w.size > w.max {
		_ = w.f.Close()
		_ = os.Rename(w.path, w.path+".1")
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err == nil {
			w.f = f
			w.size = 0
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}
