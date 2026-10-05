package system

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 时间同步守护的核心操作。目标：无论服务器装没装 NTP、在哪个国家、UDP 123 通不通，
// 都把系统时钟拉到正确时间，并保持下去。
//
//   1. 优先用已安装的 NTP 守护进程（chrony / ntpd / ntpsec / openntpd / systemd-timesyncd）
//   2. 一个都没有：apt 装 systemd-timesyncd，dnf/yum 装 chrony
//   3. timesyncd 写入多地区服务器列表（Cloudflare / Google / Apple / 阿里云 / 腾讯云 / pool）
//   4. NTP 不可达（UDP 被封）：按多个 HTTPS 站点的 Date 头取中位数直接校正系统时钟

// TimeStatus 是时间同步状态快照（API 原样返回给前端）。
type TimeStatus struct {
	// Synced 内核时钟是否已被 NTP 校准（adjtimex STA_UNSYNC），nil = 无法读取
	Synced *bool `json:"synced"`
	// NTPService 当前活动的 NTP 守护进程单元名，空 = 没有在跑
	NTPService string `json:"ntpService"`
	// NTPEnabled timedatectl 的 NTP=yes，nil = 没有 timedatectl
	NTPEnabled *bool `json:"ntpEnabled"`
	// Timezone 系统时区（timedatectl / /etc/timezone）
	Timezone string `json:"timezone"`
	// Now 服务器当前 Unix 秒（前端用来和浏览器时间对比）
	Now int64 `json:"now"`
	// Manageable 本机能否由面板管理时间（有 timedatectl）
	Manageable bool `json:"manageable"`

	// 下面由 TimeGuard 填充
	// HTTPOffset 最近一次 HTTP 校验测得的偏差（秒，本机 - 真实），nil = 未校验
	HTTPOffset    *float64 `json:"httpOffset"`
	HTTPCheckedAt int64    `json:"httpCheckedAt"`
	// LastAction 最近一次自动/手动处理的说明
	LastAction   string `json:"lastAction"`
	LastActionAt int64  `json:"lastActionAt"`
	// State 综合判定：synced（NTP 已校准）/ http（NTP 不可用但已按 HTTP 校正）/ unsynced / unknown
	State string `json:"state"`
}

// 常见 NTP 守护进程（systemd 单元名）。timesyncd 放最后：别的都没装才用它。
var ntpDaemons = []string{"chronyd", "chrony", "ntpd", "ntp", "ntpsec", "openntpd", "systemd-timesyncd"}

// timesyncdDropIn 写给 systemd-timesyncd 的多地区服务器列表（任一可达即可完成校时）。
const timesyncdDropIn = "/etc/systemd/timesyncd.conf.d/gost-webui.conf"

const timesyncdServers = `# 由 gost-webui 写入：覆盖全球与中国大陆均可达的 NTP 服务器，任一可达即可完成校时
[Time]
NTP=time.cloudflare.com time.google.com time.apple.com ntp.aliyun.com ntp.tencent.com
FallbackNTP=0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org time.windows.com
`

// httpTimeSources 是 NTP 不可达时的 HTTP 校时来源：取多个站点 Date 头的中位数，
// 单个站点异常不影响结果。握手时跳过证书校验（时钟不对时按本机时间必然验不过），
// 但拿到 Date 头后再用"站点声称的时间"校验证书链——见 verifyChainAt。
var httpTimeSources = []string{
	"https://www.cloudflare.com/",
	"https://www.google.com/",
	"https://www.apple.com/",
	"https://www.microsoft.com/",
	"https://www.baidu.com/",
	"https://www.aliyun.com/",
}

// maxHTTPStep 按 HTTP 校时时，偏差超过该值才调整系统时钟（HTTP Date 精度为秒）。
const maxHTTPStep = 2 * time.Second

// httpAgreeWindow 多个站点的结果相互偏差在此范围内视为一致（Date 精度 1 秒 + 往返延迟）。
const httpAgreeWindow = 10 * time.Second

// httpMinAgree 至少要有这么多个站点结果一致才采信（防单点被劫持/伪造）。
const httpMinAgree = 2

// httpTimeRoots 校验证书链用的根证书池；nil 表示系统根证书（测试注入 httptest 的自签证书）。
var httpTimeRoots *x509.CertPool

// verifyChainAt 用站点声称的时刻 at 校验 TLS 证书链是否对 host 有效。
// 攻击者在路径上伪造 Date 头时，拿不到对应域名在任何时刻都有效的证书，样本即被丢弃；
// 而本机时钟错得离谱时，真实站点的证书在它自己声称的时刻仍然有效，样本保留。
func verifyChainAt(cs *tls.ConnectionState, host string, at time.Time) error {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return errors.New("no peer certificate")
	}
	opts := x509.VerifyOptions{
		DNSName:       host,
		CurrentTime:   at,
		Roots:         httpTimeRoots,
		Intermediates: x509.NewCertPool(),
	}
	for _, c := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}

// ReadTimeStatus 读取当前时间同步状态（不含 TimeGuard 维护的字段）。
// 子进程调用都带 5 秒超时：timedatectl 背后是 D-Bus，卡住时不能把 API 请求一起拖死。
func ReadTimeStatus() TimeStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st := TimeStatus{Now: time.Now().Unix(), Manageable: hasCmd("timedatectl")}
	m := Metrics{}
	readClock(&m)
	st.Synced = m.ClockSynced
	st.NTPService = activeNTPDaemon(ctx)
	if st.Manageable {
		if out, err := run(ctx, "timedatectl", "show", "-p", "NTP", "--value"); err == nil {
			v := out == "yes"
			st.NTPEnabled = &v
		}
		if out, err := run(ctx, "timedatectl", "show", "-p", "Timezone", "--value"); err == nil && out != "" {
			st.Timezone = out
		}
	}
	if st.Timezone == "" {
		if b, err := os.ReadFile("/etc/timezone"); err == nil {
			st.Timezone = strings.TrimSpace(string(b))
		}
	}
	if st.Timezone == "" {
		st.Timezone = time.Now().Location().String()
	}
	return st
}

// unitNames 从 systemctl list-units / list-unit-files 的 --plain --no-legend 输出里取出单元名
// （去掉 .service 后缀），按首列精确匹配而不是子串匹配：openntpd.service 不该被当成 ntpd.service。
// skipStates 中的状态行（如 alias、masked）跳过。
func unitNames(out string, skipStates ...string) map[string]bool {
	names := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		skip := false
		for _, s := range skipStates {
			if len(f) > 1 && f[1] == s {
				skip = true
			}
		}
		if skip {
			continue
		}
		names[strings.TrimSuffix(f[0], ".service")] = true
	}
	return names
}

// activeNTPDaemon 返回正在运行的 NTP 守护进程单元名。
func activeNTPDaemon(ctx context.Context) string {
	if !hasCmd("systemctl") {
		return ""
	}
	out, err := run(ctx, "systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--plain")
	if err != nil {
		return ""
	}
	names := unitNames(out)
	for _, d := range ntpDaemons {
		if names[d] {
			return d
		}
	}
	return ""
}

// installedNTPDaemons 返回已安装（有真实单元文件，非 alias / masked）的 NTP 守护进程。
func installedNTPDaemons(ctx context.Context) map[string]bool {
	found := map[string]bool{}
	out, err := run(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain")
	if err != nil {
		return found
	}
	names := unitNames(out, "alias", "masked", "masked-runtime")
	for _, d := range ntpDaemons {
		if names[d] {
			found[d] = true
		}
	}
	return found
}

// ApplyProcessTimezone 让面板进程自身（以及之后拉起的 gost / sing-box 子进程）使用 tz：
// systemd 单元里固定了 Environment=TZ，Go 启动时就定死了 time.Local，仅改系统时区面板不会跟着变——
// 日配额/月配额的切日时刻、日志与通知里的时间都要以这里为准。tz 为空表示不干预。
func ApplyProcessTimezone(tz string) error {
	tz = strings.TrimSpace(tz)
	if tz == "" {
		return nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return fmt.Errorf("时区无效 %q: %w", tz, err)
	}
	time.Local = loc
	return os.Setenv("TZ", tz)
}

// EnsureTimezone 把系统时区设为 tz（已是则不动）。返回是否发生了修改。
func EnsureTimezone(ctx context.Context, tz string) (bool, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" {
		return false, nil
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return false, fmt.Errorf("时区无效：%s", tz)
	}
	if !hasCmd("timedatectl") {
		return false, errors.New("未检测到 timedatectl，无法设置系统时区")
	}
	cur, _ := run(ctx, "timedatectl", "show", "-p", "Timezone", "--value")
	if cur == tz {
		return false, nil
	}
	if out, err := run(ctx, "timedatectl", "set-timezone", tz); err != nil {
		return false, fmt.Errorf("设置时区失败：%s", out)
	}
	return true, nil
}

// enableNTP 让某个 NTP 守护进程跑起来并由 timedatectl 托管。
func enableNTP(ctx context.Context, steps *[]string) error {
	if !hasCmd("timedatectl") {
		return errors.New("未检测到 timedatectl（非 systemd 环境或容器内），请在宿主机启用 NTP 时间同步")
	}
	installed := installedNTPDaemons(ctx)
	other := ""
	for _, d := range ntpDaemons[:len(ntpDaemons)-1] {
		if installed[d] {
			other = d
			break
		}
	}
	switch {
	case other != "":
		// 已装 chrony / ntpd 之类：直接用它，不再装第二个（两个守护进程会互相打架）
		if out, err := run(ctx, "systemctl", "enable", "--now", other); err != nil {
			*steps = append(*steps, fmt.Sprintf("启动 %s 失败：%s", other, out))
		} else {
			*steps = append(*steps, "已启用现有 NTP 服务 "+other)
		}
	case installed["systemd-timesyncd"]:
		writeTimesyncdServers(ctx, steps)
	default:
		if err := installNTPDaemon(ctx, steps); err != nil {
			return err
		}
	}
	return enableNTPService(ctx, steps)
}

// ntpInstallRetry 安装 NTP 服务失败后的重试间隔：守护在 http 状态下每 30 分钟复查一次，
// 不能每次都把 apt-get install → update → install 整套重跑。
const ntpInstallRetry = 6 * time.Hour

var ntpInstall struct {
	sync.Mutex
	failedAt time.Time
}

// installNTPDaemon 安装 NTP 守护进程；最近 ntpInstallRetry 内失败过则直接跳过并返回原因。
func installNTPDaemon(ctx context.Context, steps *[]string) error {
	ntpInstall.Lock()
	failedAt := ntpInstall.failedAt
	ntpInstall.Unlock()
	if !failedAt.IsZero() && time.Since(failedAt) < ntpInstallRetry {
		return fmt.Errorf("上次安装 NTP 服务失败（%s 前），%d 小时内不再重试，先按 HTTP 校时",
			time.Since(failedAt).Round(time.Minute), int(ntpInstallRetry.Hours()))
	}
	err := installNTPDaemonNow(ctx, steps)
	ntpInstall.Lock()
	if err != nil {
		ntpInstall.failedAt = time.Now()
	} else {
		ntpInstall.failedAt = time.Time{}
	}
	ntpInstall.Unlock()
	return err
}

// enableNTPService 让 timedatectl 托管已就绪的 NTP 守护进程。
func enableNTPService(ctx context.Context, steps *[]string) error {
	if out, err := run(ctx, "timedatectl", "set-ntp", "true"); err != nil {
		// 极少数系统 set-ntp 对 chrony 之类不生效（没有注册 ntp-units.d），守护进程本身已启动即可
		if activeNTPDaemon(ctx) == "" {
			return fmt.Errorf("启用 NTP 失败：%s", out)
		}
		*steps = append(*steps, "timedatectl set-ntp 不支持当前 NTP 服务，已改为直接启动守护进程")
		return nil
	}
	*steps = append(*steps, "已执行 timedatectl set-ntp true")
	return nil
}

// writeTimesyncdServers 给 systemd-timesyncd 写入多地区服务器列表（已存在则不覆盖）。
func writeTimesyncdServers(ctx context.Context, steps *[]string) {
	if _, err := os.Stat(timesyncdDropIn); err == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(timesyncdDropIn), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(timesyncdDropIn, []byte(timesyncdServers), 0o644); err != nil {
		return
	}
	*steps = append(*steps, "已为 systemd-timesyncd 配置多地区 NTP 服务器")
	// 正在运行则重启以加载新列表（未运行的交给 set-ntp true 拉起）
	if activeNTPDaemon(ctx) == "systemd-timesyncd" {
		_, _ = run(ctx, "systemctl", "restart", "systemd-timesyncd")
	}
}

func installNTPDaemonNow(ctx context.Context, steps *[]string) error {
	switch {
	case hasCmd("apt-get"):
		*steps = append(*steps, "系统没有 NTP 服务，安装 systemd-timesyncd …")
		// DPkg::Lock::Timeout：刚开机时 unattended-upgrades 常常占着锁，等它 2 分钟而不是立刻失败
		aptInstall := []string{"install", "-y", "-qq", "-o", "DPkg::Lock::Timeout=120", "--no-install-recommends", "systemd-timesyncd"}
		if out, err := runPkg(ctx, "apt-get", aptInstall...); err != nil {
			// 软件源列表可能过期/缺失，更新一次再试
			_, _ = runPkg(ctx, "apt-get", "update", "-qq", "-o", "DPkg::Lock::Timeout=120")
			if out2, err2 := runPkg(ctx, "apt-get", aptInstall...); err2 != nil {
				return fmt.Errorf("安装 systemd-timesyncd 失败：%s", firstNonEmpty(out2, out))
			}
		}
		writeTimesyncdServers(ctx, steps)
		_, _ = run(ctx, "systemctl", "enable", "--now", "systemd-timesyncd")
		*steps = append(*steps, "systemd-timesyncd 已安装并启动")
	case hasCmd("dnf") || hasCmd("yum"):
		pm := "dnf"
		if !hasCmd("dnf") {
			pm = "yum"
		}
		*steps = append(*steps, "系统没有 NTP 服务，安装 chrony …")
		if out, err := runPkg(ctx, pm, "install", "-y", "-q", "chrony"); err != nil {
			return fmt.Errorf("安装 chrony 失败：%s", out)
		}
		if out, err := run(ctx, "systemctl", "enable", "--now", "chronyd"); err != nil {
			return fmt.Errorf("启动 chronyd 失败：%s", out)
		}
		*steps = append(*steps, "chrony 已安装并启动")
	default:
		return errors.New("未识别的包管理器，请手动安装 chrony 或 systemd-timesyncd 后执行 timedatectl set-ntp true")
	}
	return nil
}

// waitSynced 等待内核标记时钟已同步。
func waitSynced(ctx context.Context, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		m := Metrics{}
		readClock(&m)
		if m.ClockSynced != nil && *m.ClockSynced {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
}

// HTTPTimeOffset 并发请求多个 HTTPS 站点，按 Date 头计算"本机时间 - 真实时间"的中位数。
// 每个样本都要求证书链在站点声称的时刻对该域名有效（verifyChainAt），并且至少
// httpMinAgree 个站点结果一致，才返回结果。
func HTTPTimeOffset(ctx context.Context) (time.Duration, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	client := &http.Client{
		Timeout: 6 * time.Second,
		// 不跟随跳转：3xx 响应同样带 Date 头，且证书链必须属于我们请求的那个域名
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 握手后按站点声称时刻另行校验证书链
			DisableKeepAlives: true,
			Proxy:             nil,
		},
	}
	type sample struct {
		off time.Duration
		src string
	}
	var mu sync.Mutex
	var samples []sample
	var rejected []string
	var wg sync.WaitGroup
	for _, u := range httpTimeSources {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
			if err != nil {
				return
			}
			start := time.Now()
			res, err := client.Do(req)
			if err != nil {
				return
			}
			res.Body.Close()
			remote, err := http.ParseTime(res.Header.Get("Date"))
			if err != nil {
				return
			}
			host := hostOf(u)
			if err := verifyChainAt(res.TLS, hostnameOnly(host), remote); err != nil {
				mu.Lock()
				rejected = append(rejected, host)
				mu.Unlock()
				return
			}
			// 用请求中点近似服务器打 Date 头的时刻，抵消往返延迟
			local := start.Add(time.Since(start) / 2)
			mu.Lock()
			samples = append(samples, sample{off: local.Sub(remote), src: host})
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	if len(samples) == 0 {
		if len(rejected) > 0 {
			return 0, "", fmt.Errorf("HTTP 校时站点证书校验均未通过（%s），疑似链路被劫持，拒绝采用", strings.Join(rejected, "/"))
		}
		return 0, "", errors.New("所有 HTTP 校时站点均不可达")
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].off < samples[j].off })
	mid := samples[len(samples)/2]
	agree := 0
	srcs := make([]string, 0, len(samples))
	for _, s := range samples {
		if d := s.off - mid.off; d >= -httpAgreeWindow && d <= httpAgreeWindow {
			agree++
			srcs = append(srcs, s.src)
		}
	}
	if agree < httpMinAgree {
		return 0, "", fmt.Errorf("HTTP 校时站点结果不一致（仅 %d 个可信样本），拒绝采用", agree)
	}
	return mid.off, strings.Join(srcs, "/"), nil
}

// StepClock 把系统时钟调整 delta（正值拨快）。需要 root（CAP_SYS_TIME）。
func StepClock(delta time.Duration) error {
	target := time.Now().Add(delta)
	tv := syscall.NsecToTimeval(target.UnixNano())
	if err := syscall.Settimeofday(&tv); err != nil {
		return fmt.Errorf("settimeofday: %w（容器内通常没有 CAP_SYS_TIME 权限）", err)
	}
	// 顺手写回硬件时钟，重启后不再从错误时间起步（失败无妨）
	if hasCmd("hwclock") {
		_, _ = run(context.Background(), "hwclock", "--systohc")
	}
	return nil
}

// FixResult 是一次校时流程的结果。
type FixResult struct {
	// Steps 逐步说明（给用户看）
	Steps []string
	// NTPSynced 本次流程结束时时钟是否已由 NTP 校准
	NTPSynced bool
	// HTTPOffset 本次 HTTP 校验测得的偏差（秒，本机 - 真实）；未做 HTTP 校验时为 nil。
	// 已按 HTTP 校正过时钟时为校正后的残余偏差（0）。
	HTTPOffset *float64
}

// Report 把逐步说明拼成多行文本。
func (r FixResult) Report() string { return strings.Join(r.Steps, "\n") }

// Fix 一次完整的校时流程：时区 → 启用/安装 NTP → 等待校准 → HTTP 兜底。
// error 仅在时钟最终仍无法校准时返回。
func Fix(ctx context.Context, timezone string, wait time.Duration) (FixResult, error) {
	var r FixResult
	if timezone != "" {
		if changed, err := EnsureTimezone(ctx, timezone); err != nil {
			r.Steps = append(r.Steps, err.Error())
		} else if changed {
			r.Steps = append(r.Steps, "系统时区已设为 "+timezone)
		}
	}
	st := ReadTimeStatus()
	if st.Synced != nil && *st.Synced && st.NTPService != "" {
		r.Steps = append(r.Steps, "系统时钟已由 NTP 同步（"+st.NTPService+"）")
		r.NTPSynced = true
		return r, nil
	}

	ntpErr := enableNTP(ctx, &r.Steps)
	if ntpErr == nil {
		if waitSynced(ctx, wait) {
			r.Steps = append(r.Steps, "系统时钟已完成 NTP 校准")
			r.NTPSynced = true
			return r, nil
		}
		r.Steps = append(r.Steps, fmt.Sprintf("NTP 已启用，但 %d 秒内未完成校准（UDP 123 可能被屏蔽），改用 HTTP 校时兜底", int(wait.Seconds())))
	} else {
		r.Steps = append(r.Steps, ntpErr.Error())
	}

	off, src, err := HTTPTimeOffset(ctx)
	if err != nil {
		r.Steps = append(r.Steps, err.Error())
		return r, errors.New("无法校准系统时间：NTP 与 HTTP 校时均不可用")
	}
	sec := off.Seconds()
	r.HTTPOffset = &sec
	r.Steps = append(r.Steps, fmt.Sprintf("HTTP 校验（%s）：本机时间偏差 %+.1f 秒", src, sec))
	if math.Abs(sec) > maxHTTPStep.Seconds() {
		if err := StepClock(-off); err != nil {
			r.Steps = append(r.Steps, err.Error())
			return r, errors.New("时钟偏差过大且无法调整：" + err.Error())
		}
		zero := 0.0
		r.HTTPOffset = &zero
		r.Steps = append(r.Steps, "已按 HTTP 时间校正系统时钟")
	} else {
		r.Steps = append(r.Steps, "偏差在允许范围内，无需调整")
	}
	return r, nil
}

func hostOf(u string) string {
	u = strings.TrimPrefix(u, "https://")
	return strings.TrimSuffix(u, "/")
}

// hostnameOnly 去掉 host:port 里的端口（证书校验只看主机名 / IP）。
func hostnameOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// run 执行命令并返回合并后的输出（去首尾空白，便于拼进错误信息）。
func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// runPkg 执行包管理器命令。与 run 的区别：超时/取消时只发 SIGINT 让 apt/dnf 自行中止回滚，
// 再最多等 2 分钟，而不是直接 SIGKILL——dpkg 事务被强杀会留下"半配置"状态，之后所有安装都会报错。
func runPkg(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 2 * time.Minute
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
