package store

import (
	"bytes"
	"os"
	"testing"
	"time"

	"gost-webui/internal/model"
)

// 备份文件不能携带登录令牌（连已释放页面里的残留字节也不能有），但节点与设置必须完整。
func TestBackupExcludesSessionsKeepsData(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	const token = "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := st.SaveSession(token, Session{User: "admin", ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("site_title", "my-panel"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveNode(&model.Node{ID: "n1", Name: "node-one", Mode: "gost", ListenPort: 40001}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := st.BackupTo(&buf); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if bytes.Contains(buf.Bytes(), []byte(token)) {
		t.Fatal("备份文件里仍能找到会话令牌")
	}

	restored := dir + "/restored.db"
	if err := os.WriteFile(restored, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if v, _ := st2.GetSetting("site_title"); v != "my-panel" {
		t.Fatalf("设置未保留: %q", v)
	}
	nodes, err := st2.ListNodes()
	if err != nil || len(nodes) != 1 || nodes[0].Name != "node-one" {
		t.Fatalf("节点未保留: %v %v", nodes, err)
	}
	if _, ok := st2.GetSession(token); ok {
		t.Fatal("恢复后的库不应还有旧会话")
	}
}
