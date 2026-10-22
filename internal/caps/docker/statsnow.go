package docker

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// Now is what `stats` tells about one running container right now: the numbers `docker stats`
// shows, with what it adds to the state's cpu and memory (the memory limit, the network and disk
// totals, the processes). Numbers only; nothing the container says reaches it.
type Now struct {
	CPU        float64 `json:"cpu"`
	Mem        uint64  `json:"mem"`
	MemLimit   uint64  `json:"mem_limit"`
	MemPct     float64 `json:"mem_pct"`
	NetRx      uint64  `json:"net_rx"`
	NetTx      uint64  `json:"net_tx"`
	BlockRead  uint64  `json:"block_read"`
	BlockWrite uint64  `json:"block_write"`
	Pids       uint64  `json:"pids"`
}

type fullStats struct {
	engineStats
	PidsStats struct {
		Current uint64 `json:"current"`
	} `json:"pids_stats"`
	BlkioStats struct {
		IOServiceBytes []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
}

// nowFrom turns the engine's answer into Now (separate from the call, for the tests).
func nowFrom(s fullStats) Now {
	u := figures(s.engineStats, nil, time.Now())
	n := Now{CPU: u.cpu, Mem: uint64(u.mem), MemLimit: s.MemoryStats.Limit, MemPct: u.memPct,
		NetRx: uint64(u.rxTotal), NetTx: uint64(u.txTotal), Pids: s.PidsStats.Current}
	for _, b := range s.BlkioStats.IOServiceBytes {
		switch strings.ToLower(b.Op) {
		case "read":
			n.BlockRead += b.Value
		case "write":
			n.BlockWrite += b.Value
		}
	}
	return n
}

// statsNow reads one container's numbers: a stopped container has none.
func (d *Docker) statsNow(ctx context.Context, target string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var s fullStats
	if err := d.call(ctx, "GET", "/containers/"+url.PathEscape(target)+"/stats?stream=false", &s); err != nil {
		return "", err
	}
	out, err := json.Marshal(nowFrom(s))
	return string(out), err
}
