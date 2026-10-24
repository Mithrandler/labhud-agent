// Package pve controls the guests of the Proxmox node the agent runs on, through its local API
// (https://localhost:8006) with a token made at install (VM.PowerMgmt, VM.Audit, Sys.Audit).
// The token stays on the host. TLS is checked against the cluster's own CA.
package pve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

type PVE struct {
	URL, Token string
	Client     *http.Client
	Poll       time.Duration // between two looks at a task
	Peers      []Peer        // the nodes a guest may be moved to (LABHUD_PVE_PEERS)

	mu    sync.Mutex
	node  string
	types map[string]string // vmid -> qemu | lxc, from the last state
}

// New gives nil without a token. root is where the host's / is (for the cluster CA).
func New(apiURL, token, root string) *PVE {
	if token == "" {
		return nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(filepath.Join(root, "etc/pve/pve-root-ca.pem")); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return &PVE{URL: strings.TrimRight(apiURL, "/"), Token: token, Poll: time.Second,
		Client: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}
}

func (p *PVE) Name() string { return "pve" }

func (p *PVE) call(ctx context.Context, method, path string, out any) error {
	return p.callForm(ctx, method, path, nil, out)
}

// callForm: a call with a form body (Proxmox takes its parameters so).
func (p *PVE) callForm(ctx context.Context, method, path string, form url.Values, out any) error {
	var reqBody io.Reader
	if form != nil {
		reqBody = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL+"/api2/json"+path, reqBody)
	if err != nil {
		return err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Authorization", "PVEAPIToken="+p.Token)
	r, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if r.StatusCode >= 300 {
		msg := strings.TrimSpace(r.Status)
		if r.StatusCode == 401 || r.StatusCode == 403 {
			msg += " (the token lacks a right: VM.PowerMgmt, VM.Audit, Sys.Audit; snapshots VM.Snapshot, backups Datastore.Audit, console VM.Console, migration VM.Migrate)"
		}
		return errors.New("proxmox: " + msg)
	}
	var env struct{ Data json.RawMessage }
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

// localNode: the node this agent runs on, from the cluster status.
func (p *PVE) localNode(ctx context.Context) (string, error) {
	p.mu.Lock()
	n := p.node
	p.mu.Unlock()
	if n != "" {
		return n, nil
	}
	var st []struct {
		Type, Name string
		Local      int
	}
	if err := p.call(ctx, "GET", "/cluster/status", &st); err != nil {
		return "", err
	}
	for _, s := range st {
		if s.Type == "node" && s.Local == 1 {
			p.mu.Lock()
			p.node = s.Name
			p.mu.Unlock()
			return s.Name, nil
		}
	}
	return "", errors.New("proxmox: this node is not in the cluster status")
}

func pct(a, b float64) any {
	if b <= 0 {
		return nil
	}
	return math.Round(1000*a/b) / 10
}

var tagSplit = regexp.MustCompile(`[;, ]`)

func (p *PVE) Fill(ctx context.Context, st *proto.State) {
	node, err := p.localNode(ctx)
	if err != nil {
		return
	}
	var rs []struct {
		VMID                       int
		Name, Type, Status, Node   string
		Tags                       string
		CPU                        float64
		Mem, MaxMem, MaxDisk, Disk float64
		Uptime                     int64
		Template                   int
	}
	if err := p.call(ctx, "GET", "/cluster/resources?type=vm", &rs); err != nil {
		return
	}
	guests := map[string]map[string]any{}
	types := map[string]string{}
	for _, r := range rs {
		if r.Node != node {
			continue
		}
		id := fmt.Sprint(r.VMID)
		tags := []string{}
		for _, t := range tagSplit.Split(r.Tags, -1) {
			if t != "" {
				tags = append(tags, strings.ToLower(t))
			}
		}
		sort.Strings(tags)
		running := r.Status == "running"
		g := map[string]any{"name": r.Name, "running": running, "type": r.Type,
			"cpu": math.Round(1000*r.CPU) / 10, "mem": pct(r.Mem, r.MaxMem),
			"mem_bytes": r.Mem, "mem_max": r.MaxMem, "disk": r.MaxDisk, "uptime": r.Uptime, "tags": tags}
		if r.Template == 1 {
			g["template"] = true
		}
		if running && r.Type == "lxc" {
			g["disk_used"], g["disk_total"] = r.Disk, r.MaxDisk
		}
		guests[id] = g
		types[id] = r.Type
	}
	st.Guests, st.Node = guests, node
	for _, pr := range p.Peers {
		st.Peers = append(st.Peers, pr.Name)
	}
	p.mu.Lock()
	p.types = types
	p.mu.Unlock()
}

func (p *PVE) Do(ctx context.Context, verb, target string) error {
	if verb != "start" && verb != "shutdown" && verb != "reboot" {
		return caps.ErrNoVerb
	}
	node, err := p.localNode(ctx)
	if err != nil {
		return err
	}
	p.mu.Lock()
	kind := p.types[target]
	p.mu.Unlock()
	if kind != "qemu" && kind != "lxc" {
		return fmt.Errorf("no guest %s on %s", target, node)
	}
	var upid string
	base := "/nodes/" + url.PathEscape(node)
	if err := p.call(ctx, "POST", base+"/"+kind+"/"+target+"/status/"+verb, &upid); err != nil {
		return err
	}
	return p.wait(ctx, base, upid, false)
}

// wait follows a task until it stops. A task still going when the command's time is over is no
// failure for a shutdown (soft), a failure for anything else.
func (p *PVE) wait(ctx context.Context, base, upid string, strict bool) error {
	for {
		select {
		case <-ctx.Done():
			if strict {
				return errors.New("proxmox: the task is still running; see Tasks")
			}
			return nil
		case <-time.After(p.Poll):
		}
		var t struct{ Status, ExitStatus string }
		if err := p.call(ctx, "GET", base+"/tasks/"+url.PathEscape(upid)+"/status", &t); err != nil {
			if ctx.Err() != nil {
				continue
			}
			return err
		}
		if t.Status == "stopped" {
			if t.ExitStatus != "OK" {
				return errors.New("proxmox: " + t.ExitStatus)
			}
			return nil
		}
	}
}
