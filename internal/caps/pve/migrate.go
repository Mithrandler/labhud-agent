package pve

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// MigrateTime: a guest's disks cross the network; past this the task goes on in Proxmox (see Tasks).
const MigrateTime = 6 * time.Hour

// Peer is another Proxmox node a guest may be moved to. The two nodes need not be in a cluster:
// the move is Proxmox's own remote migration, made with a token of the target (which keeps its
// rights: VM.Allocate, Datastore.AllocateSpace, SDN.Use on the bridge, Sys.Audit) and the target's
// certificate fingerprint. Name, address and token never leave this host.
type Peer struct {
	Name, Host, Fingerprint, Token, Bridge, Storage string
}

var (
	peerName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	peerHost = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,255}$`)
	peerFP   = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)
	peerTok  = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+=[0-9a-f-]{36}$`)
	peerRef  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$`)
)

// ParsePeers reads "name|host[:port]|fingerprint|user@realm!token=uuid|bridge|storage", several
// separated by ";". Every one must be whole: a bad one is an error and none is used.
func ParsePeers(s string) ([]Peer, error) {
	var out []Peer
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f := strings.Split(part, "|")
		if len(f) != 6 {
			return nil, errors.New("a peer is name|host|fingerprint|token|bridge|storage")
		}
		p := Peer{Name: f[0], Host: f[1], Fingerprint: strings.ToUpper(f[2]), Token: f[3], Bridge: f[4], Storage: f[5]}
		switch {
		case !peerName.MatchString(p.Name) || seen[p.Name]:
			return nil, fmt.Errorf("peer name %q", p.Name)
		case !peerHost.MatchString(p.Host):
			return nil, fmt.Errorf("peer %s: address", p.Name)
		case !peerFP.MatchString(p.Fingerprint):
			return nil, fmt.Errorf("peer %s: fingerprint", p.Name)
		case !peerTok.MatchString(p.Token):
			return nil, fmt.Errorf("peer %s: token", p.Name)
		case !peerRef.MatchString(p.Bridge) || !peerRef.MatchString(p.Storage):
			return nil, fmt.Errorf("peer %s: bridge or storage", p.Name)
		}
		seen[p.Name] = true
		out = append(out, p)
	}
	return out, nil
}

// endpoint is Proxmox's "target-endpoint" value.
func (pr Peer) endpoint() string {
	host, port := pr.Host, ""
	if h, p, ok := strings.Cut(host, ":"); ok && !strings.Contains(p, ":") && !strings.HasPrefix(host, "[") {
		host, port = h, p
	}
	e := "apitoken=PVEAPIToken=" + pr.Token + ",host=" + host
	if port != "" {
		e += ",port=" + port
	}
	return e + ",fingerprint=" + pr.Fingerprint
}

// migrate moves the guest to a peer as a new guest with the same number; the original stays on
// this node, stopped (nothing is deleted here). arg is "peer:online" or "peer:offline", then
// optionally ":number" for a guest number that is taken on the other node (else the same number):
// online moves a running VM live and restarts a running LXC on the other node, offline wants it stopped.
func (p *PVE) migrate(ctx context.Context, node, kind, base, target, arg string) error {
	name, rest, _ := strings.Cut(arg, ":")
	mode, newID, _ := strings.Cut(rest, ":")
	if newID != "" {
		target = newID
	}
	var peer *Peer
	for i := range p.Peers {
		if p.Peers[i].Name == name {
			peer = &p.Peers[i]
		}
	}
	if peer == nil {
		return fmt.Errorf("no peer %s on this host (install-agent.sh --pve-peer)", name)
	}
	form := url.Values{"target-endpoint": {peer.endpoint()}, "target-vmid": {target},
		"target-bridge": {peer.Bridge}, "target-storage": {peer.Storage}}
	if mode == "online" {
		if kind == "qemu" {
			form.Set("online", "1")
		} else {
			form.Set("restart", "1")
		}
	}
	err := p.task(ctx, "POST", base+"/remote_migrate", form, node)
	if err != nil {
		// Proxmox's text may quote the endpoint, token included
		return errors.New(strings.ReplaceAll(err.Error(), peer.Token, "***"))
	}
	return nil
}
