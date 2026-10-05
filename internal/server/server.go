// Package server 提供面板的 HTTP API 与静态资源。
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gost-webui/internal/cert"
	"gost-webui/internal/config"
	"gost-webui/internal/controller"
	"gost-webui/internal/store"
	"gost-webui/internal/system"
)

// Server 面板 HTTP 服务。
type Server struct {
	cfg      *config.Config
	ctl      *controller.Controller
	log      *slog.Logger
	web      fs.FS
	mux      *http.ServeMux
	sess     *sessionStore
	basePath string
	started  time.Time

	restartMu sync.Mutex
	restartFn func()

	mu       sync.Mutex
	failures map[string]*loginFailure
	hostIP   string
	hostTime time.Time

	// 独立订阅监听器与证书管理器。
	subMu    sync.Mutex
	subSrv   *http.Server
	subCtx   context.Context
	certProv *cert.Provider
	// subErr 最近一次订阅监听器启动失败的原因（nil 表示监听正常）。
	subErr error
	// timeGuard 时间同步守护（可为 nil）
	timeGuard *system.TimeGuard
}

// New 创建服务。
func New(cfg *config.Config, ctl *controller.Controller, web fs.FS, log *slog.Logger) *Server {
	s := &Server{
		cfg:      cfg,
		ctl:      ctl,
		log:      log,
		web:      web,
		mux:      http.NewServeMux(),
		sess:     newSessionStore(ctl.Store),
		basePath: config.NormalizeBasePath(cfg.BasePath),
		started:  time.Now(),
		failures: map[string]*loginFailure{},
	}
	s.routes()
	// 订阅监听端口也要随节点端口一起放行
	ctl.ExtraPorts = func() []int { return []int{s.readSubSettings().Port} }
	return s
}

// SetRestartFunc 注册重启面板的回调。
func (s *Server) SetRestartFunc(fn func()) {
	s.restartMu.Lock()
	s.restartFn = fn
	s.restartMu.Unlock()
}

// BasePath 返回当前访问路径前缀。
func (s *Server) BasePath() string { return s.basePath }

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/session", s.auth(s.handleSession))

	s.mux.HandleFunc("GET /api/overview", s.auth(s.handleOverview))
	s.mux.HandleFunc("GET /api/nodes", s.auth(s.handleListNodes))
	s.mux.HandleFunc("POST /api/nodes", s.auth(s.handleCreateNode))
	s.mux.HandleFunc("GET /api/nodes/{id}", s.auth(s.handleGetNode))
	s.mux.HandleFunc("PUT /api/nodes/{id}", s.auth(s.handleUpdateNode))
	s.mux.HandleFunc("DELETE /api/nodes/{id}", s.auth(s.handleDeleteNode))
	s.mux.HandleFunc("POST /api/nodes/{id}/toggle", s.auth(s.handleToggleNode))
	s.mux.HandleFunc("POST /api/nodes/{id}/reset", s.auth(s.handleResetNode))
	s.mux.HandleFunc("GET /api/nodes/{id}/stats", s.auth(s.handleNodeStats))
	s.mux.HandleFunc("GET /api/nodes/{id}/link", s.auth(s.handleNodeLink))
	s.mux.HandleFunc("GET /api/nodes/{id}/qrcode", s.auth(s.handleQRCode))
	s.mux.HandleFunc("GET /api/nodes/{id}/deploy", s.auth(s.handleNodeDeploy))

	s.mux.HandleFunc("POST /api/parse", s.auth(s.handleParseLink))
	s.mux.HandleFunc("POST /api/test-connect", s.auth(s.handleTestConnect))
	s.mux.HandleFunc("GET /api/settings", s.auth(s.handleGetSettings))
	s.mux.HandleFunc("PUT /api/settings", s.auth(s.handleUpdateSettings))
	s.mux.HandleFunc("POST /api/password", s.auth(s.handleChangePassword))
	s.mux.HandleFunc("GET /api/brand", s.handleBrand)
	s.mux.HandleFunc("GET /api/backup", s.auth(s.handleBackup))
	s.mux.HandleFunc("POST /api/backup/restore", s.auth(s.handleBackupRestore))

	s.mux.HandleFunc("GET /api/system", s.auth(s.handleSystemInfo))
	s.mux.HandleFunc("GET /api/reality/available", s.auth(s.handleRealityAvailable))
	s.mux.HandleFunc("POST /api/reality/credential", s.auth(s.handleRealityCredential))
	s.mux.HandleFunc("GET /api/reality/sni", s.auth(s.handleRealitySNI))
	s.mux.HandleFunc("PUT /api/system", s.auth(s.handleSystemUpdate))
	s.mux.HandleFunc("POST /api/system/restart", s.auth(s.handleSystemRestart))
	s.mux.HandleFunc("GET /api/system/time", s.auth(s.handleSystemTime))
	s.mux.HandleFunc("POST /api/system/time-sync", s.auth(s.handleSystemTimeSync))

	s.mux.HandleFunc("GET /api/notify", s.auth(s.handleNotifyGet))
	s.mux.HandleFunc("PUT /api/notify", s.auth(s.handleNotifyPut))
	s.mux.HandleFunc("POST /api/notify/test", s.auth(s.handleNotifyTest))

	s.mux.HandleFunc("GET /api/gost", s.auth(s.handleGostStatus))
	s.mux.HandleFunc("POST /api/gost/restart", s.auth(s.handleGostRestart))
	s.mux.HandleFunc("GET /api/gost/logs", s.auth(s.handleGostLogs))
	s.mux.HandleFunc("GET /api/ports/free", s.auth(s.handleFreePort))

	// 按节点订阅管理（需登录）
	s.mux.HandleFunc("GET /api/nodes/{id}/subscription", s.auth(s.handleNodeSubscription))
	s.mux.HandleFunc("POST /api/nodes/{id}/subscription/reset", s.auth(s.handleNodeSubscriptionReset))
	s.mux.HandleFunc("GET /api/qrcode", s.auth(s.handleQRText))

	// 订阅与证书配置（需登录）
	s.mux.HandleFunc("GET /api/sub-config", s.auth(s.handleSubConfigGet))
	s.mux.HandleFunc("PUT /api/sub-config", s.auth(s.handleSubConfigPut))
	s.mux.HandleFunc("POST /api/cert/issue", s.auth(s.handleCertIssue))

	s.mux.HandleFunc("/", s.handleStatic)
}

// Handler 返回 http.Handler（支持访问路径前缀）。
func (s *Server) Handler() http.Handler {
	if s.basePath == "" {
		return s.mux
	}
	outer := http.NewServeMux()
	outer.Handle(s.basePath+"/", http.StripPrefix(s.basePath, s.mux))
	// 访问前缀本身（不带斜杠）时补一个斜杠
	outer.HandleFunc(s.basePath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.basePath+"/", http.StatusFound)
	})
	// 根路径给出提示
	outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.basePath+"/", http.StatusFound)
	})
	return outer
}

// sysCtx 返回与 HTTP 请求生命周期解耦、但有兜底超时的上下文，用于防火墙 / timedatectl / 引擎配置下发
// 这类系统侧副作用：浏览器中途断开不能把 ufw、firewall-cmd --reload 之类的命令杀在半路。
func sysCtx(r *http.Request) context.Context {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
	// 2 分钟后由定时器释放；调用方不需要显式 cancel
	_ = cancel
	return ctx
}

// ---------- 通用工具 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// ---------- 会话认证 ----------

type session struct {
	user    string
	expires time.Time
}

// sessionStore 会话存储：内存缓存 + bbolt 持久化（面板重启后登录态不丢）。
type sessionStore struct {
	mu sync.Mutex
	m  map[string]session
	db *store.Store
}

func newSessionStore(db *store.Store) *sessionStore {
	st := &sessionStore{m: map[string]session{}, db: db}
	if db != nil {
		_ = db.PruneSessions()
	}
	go func() {
		for range time.Tick(10 * time.Minute) {
			now := time.Now()
			st.mu.Lock()
			for k, v := range st.m {
				if now.After(v.expires) {
					delete(st.m, k)
					if st.db != nil {
						_ = st.db.DeleteSession(k)
					}
				}
			}
			st.mu.Unlock()
		}
	}()
	return st
}

const cookieName = "gost_webui_session"

func (st *sessionStore) create(user string) (string, time.Time) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	exp := time.Now().Add(7 * 24 * time.Hour)
	st.mu.Lock()
	st.m[token] = session{user: user, expires: exp}
	st.mu.Unlock()
	if st.db != nil {
		_ = st.db.SaveSession(token, store.Session{User: user, ExpiresAt: exp.Unix()})
	}
	return token, exp
}

func (st *sessionStore) get(token string) (string, bool) {
	st.mu.Lock()
	if v, ok := st.m[token]; ok {
		if time.Now().After(v.expires) {
			delete(st.m, token)
		} else {
			st.mu.Unlock()
			return v.user, true
		}
	}
	st.mu.Unlock()

	if st.db != nil {
		if ses, ok := st.db.GetSession(token); ok && time.Now().Unix() < ses.ExpiresAt {
			st.mu.Lock()
			st.m[token] = session{user: ses.User, expires: time.Unix(ses.ExpiresAt, 0)}
			st.mu.Unlock()
			return ses.User, true
		}
	}
	return "", false
}

func (st *sessionStore) remove(token string) {
	st.mu.Lock()
	delete(st.m, token)
	st.mu.Unlock()
	if st.db != nil {
		_ = st.db.DeleteSession(token)
	}
}

// removeAllExcept 使除 keep 以外的全部会话失效（改密码后调用：当前浏览器保持登录，其它地方一律重新登录）。
func (st *sessionStore) removeAllExcept(keep string) {
	st.mu.Lock()
	for k := range st.m {
		if k != keep {
			delete(st.m, k)
		}
	}
	st.mu.Unlock()
	if st.db != nil {
		_ = st.db.DeleteSessionsExcept(keep)
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		user, ok := s.sess.get(c.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "登录已过期")
			return
		}
		if user != s.adminUser() {
			writeErr(w, http.StatusUnauthorized, "账号已变更，请重新登录")
			return
		}
		next(w, r)
	}
}

// ---------- 管理员账号 ----------

func (s *Server) adminUser() string {
	if v, ok := s.ctl.Store.GetSetting("admin_user"); ok && v != "" {
		return v
	}
	return s.cfg.Admin.Username
}

// AdminUser 返回当前管理员用户名。
func (s *Server) AdminUser() string { return s.adminUser() }

func (s *Server) adminHash() (string, bool) {
	return s.ctl.Store.GetSetting("admin_hash")
}

func (s *Server) checkPassword(pass string) bool {
	if h, ok := s.adminHash(); ok {
		return bcrypt.CompareHashAndPassword([]byte(h), []byte(pass)) == nil
	}
	// 首次运行：使用配置文件中的初始密码
	want := s.cfg.Admin.Password
	if want == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1 {
		// 落库为哈希
		if h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost); err == nil {
			_ = s.ctl.Store.SetSetting("admin_hash", string(h))
			_ = s.ctl.Store.SetSetting("admin_user", s.cfg.Admin.Username)
		}
		return true
	}
	return false
}

// loginFailure 记录某个来源（或全局）的登录失败计数。
type loginFailure struct {
	count  int       // 当前计数窗口内的失败次数
	window time.Time // 计数窗口截止时间（首次失败后 1 分钟）
	until  time.Time // 锁定截止时间
}

// 登录失败限制：单来源 5 次/分钟锁 1 分钟；所有来源合计 30 次/分钟全局锁 1 分钟
// （防止反代场景下换 IP / 伪造头绕过）。
const (
	loginFailPerIP  = 5
	loginFailGlobal = 30
	loginLockFor    = time.Minute
	loginGlobalKey  = "*"
)

// loginLocked 判断该来源或全局是否处于锁定期（需持有 s.mu）。
func (s *Server) loginLocked(ip string, now time.Time) bool {
	for _, k := range [...]string{ip, loginGlobalKey} {
		if f := s.failures[k]; f != nil && now.Before(f.until) {
			return true
		}
	}
	return false
}

// recordLoginFailure 记一次失败，窗口内达到阈值则锁定；顺手清理过期条目，避免 map 无限增长（需持有 s.mu）。
func (s *Server) recordLoginFailure(ip string, now time.Time) {
	bump := func(key string, limit int) {
		f := s.failures[key]
		if f == nil || now.After(f.window) {
			f = &loginFailure{window: now.Add(loginLockFor)}
			s.failures[key] = f
		}
		f.count++
		if f.count >= limit {
			f.until = now.Add(loginLockFor)
			f.window = f.until
			f.count = 0
		}
	}
	bump(ip, loginFailPerIP)
	bump(loginGlobalKey, loginFailGlobal)
	if len(s.failures) > 512 {
		for k, f := range s.failures {
			if k != loginGlobalKey && now.After(f.window) && now.After(f.until) {
				delete(s.failures, k)
			}
		}
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	// 限流键只用真实对端地址：X-Forwarded-For 可被客户端任意伪造，用它做键等于没有限制。
	ip := remoteHost(r)
	now := time.Now()
	s.mu.Lock()
	if s.loginLocked(ip, now) {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	s.mu.Unlock()

	if strings.TrimSpace(req.Username) != s.adminUser() || !s.checkPassword(req.Password) {
		s.mu.Lock()
		s.recordLoginFailure(ip, time.Now())
		s.mu.Unlock()
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	token, exp := s.sess.create(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     s.cookiePath(),
		Expires:  exp,
		HttpOnly: true,
		Secure:   requestIsTLS(r),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": req.Username})
}

func (s *Server) cookiePath() string {
	if s.basePath == "" {
		return "/"
	}
	return s.basePath + "/"
}

// requestIsTLS 判断当前请求是否走 HTTPS（直连 TLS 或反代声明 https）。
func requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return strings.EqualFold(strings.TrimSpace(strings.Split(v, ",")[0]), "https")
	}
	return false
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sess.remove(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.cookiePath(), MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"loggedIn": true,
		"username": s.adminUser(),
	})
}

// remoteHost 返回 TCP 对端地址（不看任何转发头）。
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- 静态资源 ----------

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "接口不存在")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	f, err := s.web.Open(path)
	if err != nil {
		// 前端使用 hash 路由，未知路径一律回退到 index.html
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		s.serveIndex(w, r2)
		return
	}
	_ = f.Close()
	if path == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.FileServer(http.FS(s.web)).ServeHTTP(w, r)
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, s.web, "index.html")
}

// randomPort 在 [min,max] 中随机取一个端口。
func randomPort(min, max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// randomPassword 生成 n 位 URL 安全的随机密码（不含 +/= 等需转义字符）。
func randomPassword(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if n <= 0 {
		n = 20
	}
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			idx = big.NewInt(int64(i % len(alphabet)))
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b)
}
