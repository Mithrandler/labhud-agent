// Package ptero controls game servers through a Pterodactyl panel's client API, with a client
// key kept on the agent's host. One agent next to the panel covers every server the key sees.
package ptero

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

const (
	MaxServers = 30
	Every      = 20 * time.Second // one list + one call per server: well under the panel's limit
)

type Ptero struct {
	URL, Key string
	Client   *http.Client

	mu    sync.Mutex
	last  map[string]map[string]any
	lastT time.Time
}

// New gives nil without a panel address and a key. With pin (the hex SHA-256 of the panel's
// certificate) that certificate is accepted and no other, for a panel with a self-signed one;
// without it the system roots decide, as for any HTTPS site.
func New(panel, key, pin string) *Ptero {
	if panel == "" || key == "" {
		return nil
	}
	c := &http.Client{Timeout: 15 * time.Second}
	if pin != "" {
		c.Transport = &http.Transport{TLSClientConfig: pinned(pin)}
	}
	return &Ptero{URL: strings.TrimRight(panel, "/"), Key: key, Client: c}
}

func pinned(pin string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // the pin below is the check
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("panel: no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if got := hex.EncodeToString(sum[:]); subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return fmt.Errorf("panel: not the pinned certificate (got %s…)", got[:12])
			}
			return nil
		},
	}
}

func (p *Ptero) Name() string { return "ptero" }

func (p *Ptero) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL+"/api/client"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	r, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if r.StatusCode >= 300 {
		var e struct {
			Errors []struct{ Detail string }
		}
		if json.Unmarshal(b, &e) == nil && len(e.Errors) > 0 && e.Errors[0].Detail != "" {
			return errors.New("pterodactyl: " + e.Errors[0].Detail)
		}
		return fmt.Errorf("pterodactyl: HTTP %d", r.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (p *Ptero) read(ctx context.Context) (map[string]map[string]any, error) {
	var list struct {
		Data []struct {
			Attributes struct {
				Identifier, Name string
				IsSuspended      bool `json:"is_suspended"`
			}
		}
	}
	if err := p.call(ctx, "GET", "?per_page=100", nil, &list); err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	for _, d := range list.Data {
		if len(out) >= MaxServers {
			break
		}
		a := d.Attributes
		s := map[string]any{"name": a.Name}
		if a.IsSuspended {
			s["state"] = "suspended"
			out[a.Identifier] = s
			continue
		}
		var res struct {
			Attributes struct {
				CurrentState string `json:"current_state"`
				Resources    struct {
					MemoryBytes float64 `json:"memory_bytes"`
					CPUAbsolute float64 `json:"cpu_absolute"`
					DiskBytes   float64 `json:"disk_bytes"`
					Uptime      int64   `json:"uptime"`
				}
			}
		}
		if err := p.call(ctx, "GET", "/servers/"+url.PathEscape(a.Identifier)+"/resources", nil, &res); err != nil {
			s["state"] = "unknown"
		} else {
			r := res.Attributes.Resources
			s["state"] = res.Attributes.CurrentState
			s["cpu"] = math.Round(r.CPUAbsolute*10) / 10
			s["mem_bytes"], s["disk_bytes"], s["uptime"] = r.MemoryBytes, r.DiskBytes, r.Uptime/1000
		}
		out[a.Identifier] = s
	}
	return out, nil
}

func (p *Ptero) Fill(ctx context.Context, st *proto.State) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == nil || time.Since(p.lastT) >= Every {
		if s, err := p.read(ctx); err == nil {
			p.last, p.lastT = s, time.Now()
		}
	}
	if p.last != nil {
		st.Servers = p.last
	}
}

func (p *Ptero) Do(ctx context.Context, verb, target string) error {
	if verb != "start" && verb != "stop" && verb != "restart" {
		return caps.ErrNoVerb
	}
	err := p.call(ctx, "POST", "/servers/"+url.PathEscape(target)+"/power", map[string]string{"signal": verb}, nil)
	if err == nil {
		p.mu.Lock()
		p.lastT = time.Time{} // read again at the next state
		p.mu.Unlock()
	}
	return err
}
