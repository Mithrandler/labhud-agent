package docker

import (
	"context"
	"math"
	"net/url"
	"sync"
	"time"
)

// StatsEvery: how often the ticked containers that run are measured (each takes the engine
// about a second, so a few at a time).
const (
	StatsEvery    = 30 * time.Second
	statsParallel = 4
)

// usage is one container's numbers, as `docker stats` shows them: cpu in % of one core (200 is
// two cores busy), mem without the page cache, net in bytes a second.
type usage struct {
	cpu, mem, memPct, rx, tx float64
	restarts                 int
	rates                    bool // net_rx/net_tx known (a second measure)
	rxTotal, txTotal         float64
	at                       time.Time
}

type engineStats struct {
	CPUStats    cpuStats `json:"cpu_stats"`
	PreCPUStats cpuStats `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
}

type cpuStats struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs  uint64 `json:"online_cpus"`
}

// figures turns the engine's answer into usage; prev (the last one, maybe nil) gives the rates.
func figures(s engineStats, prev *usage, now time.Time) usage {
	u := usage{at: now}
	cpu := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sys := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if cpu > 0 && sys > 0 && s.CPUStats.OnlineCPUs > 0 {
		u.cpu = round1(cpu / sys * float64(s.CPUStats.OnlineCPUs) * 100)
	}
	mem := float64(s.MemoryStats.Usage)
	if v, ok := s.MemoryStats.Stats["inactive_file"]; ok { // cgroup v2
		mem -= float64(v)
	} else if v, ok := s.MemoryStats.Stats["total_inactive_file"]; ok { // v1
		mem -= float64(v)
	}
	u.mem = math.Max(0, mem)
	if s.MemoryStats.Limit > 0 {
		u.memPct = round1(100 * u.mem / float64(s.MemoryStats.Limit))
	}
	for _, n := range s.Networks {
		u.rxTotal += float64(n.RxBytes)
		u.txTotal += float64(n.TxBytes)
	}
	if prev != nil {
		if dt := now.Sub(prev.at).Seconds(); dt > 0 && u.rxTotal >= prev.rxTotal && u.txTotal >= prev.txTotal {
			u.rates = true
			u.rx, u.tx = math.Round((u.rxTotal-prev.rxTotal)/dt), math.Round((u.txTotal-prev.txTotal)/dt)
		}
	}
	return u
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Measure keeps the ticked, running containers' usage, every StatsEvery until ctx ends.
func (d *Docker) Measure(ctx context.Context) {
	for {
		d.measure(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(StatsEvery):
		}
	}
}

func (d *Docker) measure(ctx context.Context) {
	if d.Allow == nil {
		return
	}
	var list []struct {
		Names []string
		State string
	}
	if d.call(ctx, "GET", "/containers/json", &list) != nil { // running only
		return
	}
	ticked := map[string]bool{}
	for _, n := range d.Allow.Targets("docker") {
		ticked[n] = true
	}
	var names []string
	for _, c := range list {
		if len(c.Names) > 0 && ticked[c.Names[0][1:]] {
			names = append(names, c.Names[0][1:])
		}
	}
	d.mu.Lock()
	prev := d.usage
	d.mu.Unlock()
	next := map[string]usage{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, statsParallel)
	for _, name := range names {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			var s engineStats
			if d.call(cctx, "GET", "/containers/"+url.PathEscape(name)+"/stats?stream=false", &s) != nil {
				return
			}
			var p *usage
			if old, ok := prev[name]; ok {
				p = &old
			}
			u := figures(s, p, time.Now())
			var info struct{ RestartCount int }
			if d.call(cctx, "GET", "/containers/"+url.PathEscape(name)+"/json", &info) == nil {
				u.restarts = info.RestartCount
			}
			mu.Lock()
			next[name] = u
			mu.Unlock()
		}()
	}
	wg.Wait()
	d.mu.Lock()
	d.usage = next
	d.mu.Unlock()
}

// put adds a container's usage to its entry in the state (Fill, under d.mu).
func (u usage) put(e map[string]any) {
	e["cpu"], e["mem"], e["mem_pct"] = u.cpu, u.mem, u.memPct
	if u.rates {
		e["net_rx"], e["net_tx"] = u.rx, u.tx
	}
	if u.restarts > 0 {
		e["restarts"] = u.restarts
	}
}
