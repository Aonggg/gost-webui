// Package system 采集主机负载指标（CPU/内存/磁盘），用于面板展示与告警。
package system

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Metrics 是主机负载快照。
type Metrics struct {
	CPUCount   int     `json:"cpuCount"`
	Load1      float64 `json:"load1"`
	Load5      float64 `json:"load5"`
	Load15     float64 `json:"load15"`
	CPUPercent float64 `json:"cpuPercent"`

	MemTotal    uint64  `json:"memTotal"`
	MemUsed     uint64  `json:"memUsed"`
	MemPercent  float64 `json:"memPercent"`
	SwapTotal   uint64  `json:"swapTotal"`
	SwapUsed    uint64  `json:"swapUsed"`
	SwapPercent float64 `json:"swapPercent"`
	DiskTotal   uint64  `json:"diskTotal"`
	DiskUsed    uint64  `json:"diskUsed"`
	DiskPercent float64 `json:"diskPercent"`
	HostUptime  int64   `json:"hostUptime"`
	RuntimeOS   string  `json:"os"`
	RuntimeArch string  `json:"arch"`
	// ClockSynced 表示系统时钟是否已被 NTP 守护进程校准（nil = 无法判断）。
	// 与 timedatectl 的 "System clock synchronized" 同源：读取内核 adjtimex 状态位 STA_UNSYNC。
	ClockSynced *bool `json:"clockSynced"`
}

// Read 采集当前指标（读取失败时对应字段为 0）。
func Read() Metrics {
	m := Metrics{
		CPUCount:    runtime.NumCPU(),
		RuntimeOS:   runtime.GOOS,
		RuntimeArch: runtime.GOARCH,
	}
	readLoad(&m)
	readMem(&m)
	readDisk(&m)
	readUptime(&m)
	readClock(&m)
	if m.CPUCount > 0 {
		m.CPUPercent = round1(m.Load1 / float64(m.CPUCount) * 100)
	}
	return m
}

func readLoad(m *Metrics) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	if len(f) >= 3 {
		m.Load1, _ = strconv.ParseFloat(f[0], 64)
		m.Load5, _ = strconv.ParseFloat(f[1], 64)
		m.Load15, _ = strconv.ParseFloat(f[2], 64)
	}
}

func readMem(m *Metrics) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	vals := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		fields := strings.Fields(line[i+1:])
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		vals[key] = v * 1024
	}
	m.MemTotal = vals["MemTotal"]
	avail := vals["MemAvailable"]
	if avail == 0 {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	if m.MemTotal > 0 {
		m.MemUsed = m.MemTotal - avail
		m.MemPercent = round1(float64(m.MemUsed) / float64(m.MemTotal) * 100)
	}
	m.SwapTotal = vals["SwapTotal"]
	if m.SwapTotal > 0 {
		m.SwapUsed = m.SwapTotal - vals["SwapFree"]
		m.SwapPercent = round1(float64(m.SwapUsed) / float64(m.SwapTotal) * 100)
	}
}

func readDisk(m *Metrics) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	m.DiskTotal = total
	if total > 0 {
		m.DiskUsed = total - free
		m.DiskPercent = round1(float64(m.DiskUsed) / float64(total) * 100)
	}
}

func readUptime(m *Metrics) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	if len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			m.HostUptime = int64(v)
		}
	}
}

// staUnsync 是 linux/timex.h 中的 STA_UNSYNC：时钟未同步（NTP 守护进程成功对时后清除，
// 长时间（约 9 小时）没有再次对时则由内核重新置位）。
const staUnsync = 0x40

func readClock(m *Metrics) {
	var tx syscall.Timex
	if _, err := syscall.Adjtimex(&tx); err != nil {
		return
	}
	synced := tx.Status&staUnsync == 0
	m.ClockSynced = &synced
}

func round1(v float64) float64 {
	if v < 0 {
		v = 0
	}
	return float64(int(v*10+0.5)) / 10
}
