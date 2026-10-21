// Package sensors reads what labhud's cards show for a host: CPU, memory, disk, load, uptime,
// CPU temperature, NVIDIA GPUs and the RAPL power estimate. The keys are those of labhud's
// Python agent (agents/labhud-agent.py) and of host-temp-api, so cards keep working when a
// host moves to this agent.
package sensors

import (
	"bufio"
	"context"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Reader struct {
	Root      string        // prefix of every /proc and /sys path: "/" on a host, "/host" in a container
	NvidiaSMI string        // path to nvidia-smi, "" without one
	BaseW     float64       // fixed watts added to the estimate (board, disks, fans, PSU losses)
	PriceKWh  float64       // 0: no cost_day
	CacheFor  time.Duration // nvidia-smi takes ~100 ms: not on every read

	mu                  sync.Mutex
	lastIdle, lastTotal uint64
	raplE               uint64
	raplT               time.Time
	raplOK              bool
	cache               map[string]any
	cacheT              time.Time
	netRx, netTx        uint64
	netT                time.Time
	lastPower           map[string]any
}

func New(root string, baseW, priceKWh float64) *Reader {
	smi, err := exec.LookPath("nvidia-smi")
	if err != nil {
		smi = ""
	}
	return &Reader{Root: root, NvidiaSMI: smi, BaseW: baseW, PriceKWh: priceKWh, CacheFor: 5 * time.Second}
}

func (r *Reader) path(p string) string { return filepath.Join(r.Root, p) }

// Found says whether this looks like Linux at Root.
func (r *Reader) Found() bool {
	_, err := os.Stat(r.path("proc/stat"))
	return err == nil
}

// Read gives the sensors, at most CacheFor old. The map is the caller's.
func (r *Reader) Read() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil || time.Since(r.cacheT) >= r.CacheFor {
		r.cache, r.cacheT = r.read(), time.Now()
	}
	out := make(map[string]any, len(r.cache))
	for k, v := range r.cache {
		out[k] = v
	}
	return out
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }
func round2(x float64) float64 { return math.Round(x*100) / 100 }

func readTrim(p string) (string, error) {
	b, err := os.ReadFile(p)
	return strings.TrimSpace(string(b)), err
}

func (r *Reader) read() map[string]any {
	out := map[string]any{}
	if v, ok := r.cpuPercent(); ok {
		out["cpu"] = v
	}
	r.memory(out)
	r.disk(out)
	if s, err := readTrim(r.path("proc/loadavg")); err == nil {
		if f := strings.Fields(s); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				out["load1"] = v
			}
		}
	}
	if s, err := readTrim(r.path("proc/uptime")); err == nil {
		if f := strings.Fields(s); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				out["uptime"] = int64(v)
			}
		}
	}
	if t, ok := r.cpuTemp(); ok {
		out["cpu_temp"] = t
	}
	gpuW := r.gpus(out)
	r.power(out, gpuW)
	r.network(out)
	return out
}

// virtual: the interfaces that are not a card of their own (bridges, veths, tunnels, Docker's,
// Proxmox's firewall plumbing), for a host whose /sys does not say which are physical.
var virtual = []string{"lo", "veth", "docker", "br-", "virbr", "vmbr", "tap", "fwbr", "fwpr", "fwln", "tun", "wg", "vnet", "cali", "flannel", "cni"}

// physical: the interface has a device behind it (a PCI or USB card, or virtio in a VM).
func (r *Reader) physical(name string) bool {
	_, err := os.Stat(r.path("sys/class/net/" + name + "/device"))
	return err == nil
}

// network adds net_rx / net_tx: bytes a second, summed over the physical interfaces (all the
// non-virtual ones when none says it is physical), from /proc/net/dev between two reads.
func (r *Reader) network(out map[string]any) {
	s, err := readTrim(r.path("proc/net/dev"))
	if err != nil {
		return
	}
	type counts struct{ rx, tx uint64 }
	all := map[string]counts{}
	for _, line := range strings.Split(s, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 == nil && err2 == nil {
			all[strings.TrimSpace(name)] = counts{rx, tx}
		}
	}
	var rx, tx uint64
	phys := 0
	for name, c := range all {
		if r.physical(name) {
			rx, tx, phys = rx+c.rx, tx+c.tx, phys+1
		}
	}
	if phys == 0 {
	next:
		for name, c := range all {
			for _, v := range virtual {
				if strings.HasPrefix(name, v) {
					continue next
				}
			}
			rx, tx = rx+c.rx, tx+c.tx
		}
	}
	now := time.Now()
	prevRx, prevTx, prevT := r.netRx, r.netTx, r.netT
	r.netRx, r.netTx, r.netT = rx, tx, now
	dt := now.Sub(prevT).Seconds()
	if prevT.IsZero() || dt <= 0 || rx < prevRx || tx < prevTx { // first read, or a counter reset
		return
	}
	out["net_rx"] = int64(float64(rx-prevRx) / dt)
	out["net_tx"] = int64(float64(tx-prevTx) / dt)
}

func (r *Reader) cpuPercent() (float64, bool) {
	s, err := readTrim(r.path("proc/stat"))
	if err != nil {
		return 0, false
	}
	line, _, _ := strings.Cut(s, "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, false
	}
	var v []uint64
	for _, x := range f[1:] {
		n, err := strconv.ParseUint(x, 10, 64)
		if err != nil {
			return 0, false
		}
		v = append(v, n)
	}
	idle := v[3]
	if len(v) > 4 {
		idle += v[4]
	}
	var total uint64
	for i := 0; i < len(v) && i < 8; i++ {
		total += v[i]
	}
	dTotal, dIdle := float64(total)-float64(r.lastTotal), float64(idle)-float64(r.lastIdle)
	r.lastIdle, r.lastTotal = idle, total
	if dTotal <= 0 {
		return 0, false
	}
	return round1(100 * (dTotal - dIdle) / dTotal), true
}

func (r *Reader) memory(out map[string]any) {
	f, err := os.Open(r.path("proc/meminfo"))
	if err != nil {
		return
	}
	defer f.Close()
	mem := map[string]int64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		if fs := strings.Fields(v); len(fs) > 0 {
			if n, err := strconv.ParseInt(fs[0], 10, 64); err == nil {
				mem[k] = n * 1024
			}
		}
	}
	total, ok := mem["MemTotal"]
	if !ok || total <= 0 {
		return
	}
	avail, ok := mem["MemAvailable"]
	if !ok {
		avail = mem["MemFree"]
	}
	used := total - avail
	out["mem_used_of"] = []int64{used, total}
	out["mem"] = round1(100 * float64(used) / float64(total))
}

func (r *Reader) disk(out map[string]any) {
	var st syscall.Statfs_t
	if syscall.Statfs(r.Root, &st) != nil {
		return
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	total, free := st.Blocks*bs, st.Bavail*bs
	if total == 0 {
		return
	}
	out["disk_used_of"] = []int64{int64(total - free), int64(total)}
	out["disk"] = round1(100 * float64(total-free) / float64(total))
}

// cpuTemp: the package temperature (coretemp, k10temp or zenpower), else the hottest core.
func (r *Reader) cpuTemp() (float64, bool) {
	dirs, _ := filepath.Glob(r.path("sys/class/hwmon/hwmon*"))
	sort.Strings(dirs)
	for _, hw := range dirs {
		name, err := readTrim(filepath.Join(hw, "name"))
		if err != nil || (name != "coretemp" && name != "k10temp" && name != "zenpower") {
			continue
		}
		labels, _ := filepath.Glob(filepath.Join(hw, "temp*_label"))
		sort.Strings(labels)
		best, any := 0.0, false
		for _, l := range labels {
			label, err1 := readTrim(l)
			raw, err2 := readTrim(strings.TrimSuffix(l, "_label") + "_input")
			n, err3 := strconv.ParseFloat(raw, 64)
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			v := n / 1000
			if strings.HasPrefix(label, "Package") || label == "Tctl" {
				return round1(v), true
			}
			if !any || v > best {
				best, any = v, true
			}
		}
		if any {
			return round1(best), true
		}
	}
	return 0, false
}

// gpus adds the gpuN_* keys and gpu_count, and returns the GPUs' total watts.
func (r *Reader) gpus(out map[string]any) float64 {
	out["gpu_count"] = 0
	if r.NvidiaSMI == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, r.NvidiaSMI,
		"--query-gpu=index,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return 0
	}
	return parseGPUs(string(b), out)
}

func parseGPUs(text string, out map[string]any) float64 {
	count, watts := 0, 0.0
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		f := strings.Split(line, ",")
		if len(f) != 6 {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		idx, e1 := strconv.Atoi(f[0])
		temp, e2 := strconv.ParseFloat(f[1], 64)
		util, e3 := strconv.ParseFloat(f[2], 64)
		used, e4 := strconv.ParseFloat(f[3], 64)
		total, e5 := strconv.ParseFloat(f[4], 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || total <= 0 {
			continue
		}
		p := "gpu" + strconv.Itoa(idx) + "_"
		out[p+"util"], out[p+"temp"] = util, temp
		out[p+"mem"] = round1(used * 100 / total)
		out[p+"mem_used_mib"], out[p+"mem_total_mib"] = used, total
		if w, err := strconv.ParseFloat(f[5], 64); err == nil {
			out[p+"power"] = w
			watts += w
		}
		count++
	}
	out["gpu_count"] = count
	return watts
}

var powerKeys = []string{"power_cpu", "power_gpu", "power_base", "power", "kwh_day", "cost_day"}

// power: the CPU package from RAPL + the GPUs + BaseW, like host-temp-api.
func (r *Reader) power(out map[string]any, gpuW float64) {
	dir := r.path("sys/class/powercap/intel-rapl:0")
	s, err := readTrim(filepath.Join(dir, "energy_uj"))
	if err != nil {
		return
	}
	e, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return
	}
	now := time.Now()
	cpuW, have := 0.0, false
	if r.raplOK && now.Sub(r.raplT) >= time.Second {
		de, ok := e-r.raplE, true
		if e < r.raplE { // the counter wrapped around
			ok = false
			if m, err := readTrim(filepath.Join(dir, "max_energy_range_uj")); err == nil {
				if max, err := strconv.ParseUint(m, 10, 64); err == nil {
					de, ok = e+max-r.raplE, true
				}
			}
		}
		if ok {
			cpuW, have = round1(float64(de)/1e6/now.Sub(r.raplT).Seconds()), true
		}
	}
	r.raplE, r.raplT, r.raplOK = e, now, true
	if !have {
		for k, v := range r.lastPower { // the first sample has no delta: keep the last numbers
			out[k] = v
		}
		return
	}
	total := cpuW + round1(gpuW) + r.BaseW
	p := map[string]any{"power_cpu": cpuW, "power_gpu": round1(gpuW), "power_base": r.BaseW,
		"power": math.Round(total), "kwh_day": round2(total * 24 / 1000)}
	if r.PriceKWh > 0 {
		p["cost_day"] = round2(total * 24 / 1000 * r.PriceKWh)
	}
	for _, k := range powerKeys {
		if v, ok := p[k]; ok {
			out[k] = v
		}
	}
	r.lastPower = p
}
