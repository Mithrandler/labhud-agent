package pve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
)

// The verbs that look inside a guest: its configuration, snapshots, backups and tasks (read), and
// make, roll back or delete a snapshot. They need rights the install token does not have by
// default (VM.Snapshot, Datastore.Audit); without them Proxmox answers 403 and the message says so.
const (
	maxRows     = 100
	maxStorages = 8
	// SnapTime: a snapshot of a guest with a lot of RAM or disk may take its time.
	SnapTime = 5 * time.Minute
	// BackupTime: a backup of a big guest takes hours; past this the task goes on in Proxmox (see Tasks).
	BackupTime = 3 * time.Hour
)

// secretKey: a configuration key whose value never leaves the host.
var secretKey = regexp.MustCompile(`(?i)pass|secret|token|cicustom|sshkeys|(^|_)keys?$`)

func (p *PVE) TakesArg(verb string) bool {
	switch verb {
	case "config", "snap-list", "backup-list", "task-list", "snap-create", "snap-rollback", "snap-delete", "vzdump", "migrate":
		return true
	}
	return false
}

func (p *PVE) Timeout(verb string) time.Duration {
	switch verb {
	case "snap-create", "snap-rollback", "snap-delete":
		return SnapTime
	case "vzdump":
		return BackupTime
	case "migrate":
		return MigrateTime
	}
	return 0
}

func (p *PVE) guest(ctx context.Context, target string) (node, kind, base string, err error) {
	if node, err = p.localNode(ctx); err != nil {
		return
	}
	p.mu.Lock()
	kind = p.types[target]
	p.mu.Unlock()
	if kind != "qemu" && kind != "lxc" {
		err = fmt.Errorf("no guest %s on %s", target, node)
		return
	}
	return node, kind, "/nodes/" + url.PathEscape(node) + "/" + kind + "/" + target, nil
}

func clip(s string, n int) string {
	r := []rune(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func (p *PVE) RunArg(ctx context.Context, verb, target, arg string) (string, error) {
	node, kind, base, err := p.guest(ctx, target)
	if err != nil {
		return "", err
	}
	switch verb {
	case "config":
		var cfg map[string]any
		if err := p.call(ctx, "GET", base+"/config", &cfg); err != nil {
			return "", err
		}
		keys := make([]string, 0, len(cfg))
		for k := range cfg {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []map[string]string{}
		for _, k := range keys {
			if len(out) >= 200 {
				break
			}
			v := fmt.Sprint(cfg[k])
			if secretKey.MatchString(k) {
				v = "********"
			}
			out = append(out, map[string]string{"key": clip(k, 60), "value": clip(v, 300)})
		}
		return marshal(map[string]any{"type": kind, "config": out})
	case "snap-list":
		var rows []struct {
			Name, Description, Parent string
			SnapTime                  int64
			VMState                   int
		}
		if err := p.call(ctx, "GET", base+"/snapshot", &rows); err != nil {
			return "", err
		}
		out := []map[string]any{}
		for _, r := range rows {
			if r.Name == "current" || len(out) >= maxRows {
				continue
			}
			out = append(out, map[string]any{"name": clip(r.Name, 40), "description": clip(r.Description, 200),
				"parent": clip(r.Parent, 40), "time": r.SnapTime, "vmstate": r.VMState == 1})
		}
		return marshal(map[string]any{"snapshots": out})
	case "task-list":
		var rows []struct {
			UPID, Type, Status, User string
			StartTime, EndTime       int64
		}
		q := url.Values{"vmid": {target}, "limit": {"30"}}
		if err := p.call(ctx, "GET", "/nodes/"+url.PathEscape(node)+"/tasks?"+q.Encode(), &rows); err != nil {
			return "", err
		}
		out := []map[string]any{}
		for _, r := range rows {
			if len(out) >= 30 {
				break
			}
			out = append(out, map[string]any{"type": clip(r.Type, 30), "status": clip(r.Status, 120), "user": clip(r.User, 60),
				"start": r.StartTime, "end": r.EndTime})
		}
		return marshal(map[string]any{"tasks": out})
	case "backup-list":
		return p.backups(ctx, node, target)
	case "snap-create":
		form := url.Values{"snapname": {arg}}
		return "", p.task(ctx, "POST", base+"/snapshot", form, node)
	case "vzdump":
		// arg is "storage:mode"; the storage must be one of the node's backup storages
		storage, mode, _ := strings.Cut(arg, ":")
		var stores []struct{ Storage string }
		if err := p.call(ctx, "GET", "/nodes/"+url.PathEscape(node)+"/storage?content=backup", &stores); err != nil {
			return "", err
		}
		found := false
		for _, s := range stores {
			found = found || s.Storage == storage
		}
		if !found {
			return "", fmt.Errorf("no backup storage %s on %s", storage, node)
		}
		form := url.Values{"vmid": {target}, "storage": {storage}, "mode": {mode}, "compress": {"zstd"}}
		return "", p.task(ctx, "POST", "/nodes/"+url.PathEscape(node)+"/vzdump", form, node)
	case "snap-rollback":
		return "", p.task(ctx, "POST", base+"/snapshot/"+url.PathEscape(arg)+"/rollback", url.Values{}, node)
	case "snap-delete":
		return "", p.task(ctx, "DELETE", base+"/snapshot/"+url.PathEscape(arg), nil, node)
	case "migrate":
		return "", p.migrate(ctx, node, kind, base, target, arg)
	}
	return "", caps.ErrNoVerb
}

// task runs a call that starts a task and follows it to its end.
func (p *PVE) task(ctx context.Context, method, path string, form url.Values, node string) error {
	var upid string
	if err := p.callForm(ctx, method, path, form, &upid); err != nil {
		return err
	}
	if upid == "" {
		return errors.New("proxmox: no task came back")
	}
	return p.wait(ctx, "/nodes/"+url.PathEscape(node), upid, true)
}

func (p *PVE) backups(ctx context.Context, node, target string) (string, error) {
	var stores []struct{ Storage string }
	nb := "/nodes/" + url.PathEscape(node)
	if err := p.call(ctx, "GET", nb+"/storage?content=backup", &stores); err != nil {
		return "", err
	}
	out := []map[string]any{}
	for i, s := range stores {
		if i >= maxStorages {
			break
		}
		var items []struct {
			VolID, Format, Notes string
			Size, CTime          int64
			Protected            int
		}
		q := url.Values{"content": {"backup"}, "vmid": {target}}
		if err := p.call(ctx, "GET", nb+"/storage/"+url.PathEscape(s.Storage)+"/content?"+q.Encode(), &items); err != nil {
			return "", err
		}
		for _, it := range items {
			if len(out) >= maxRows {
				break
			}
			out = append(out, map[string]any{"storage": clip(s.Storage, 60), "volid": clip(it.VolID, 200), "size": it.Size,
				"time": it.CTime, "format": clip(it.Format, 20), "notes": clip(it.Notes, 200), "protected": it.Protected == 1})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["time"].(int64) > out[j]["time"].(int64) })
	return marshal(map[string]any{"backups": out})
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
