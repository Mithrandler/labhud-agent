// Package scan is the `scan` capability: the critical and high CVEs of the images the ticked
// containers run, from trivy (or grype) when one of them is installed on the host. Nothing is
// downloaded or installed by the agent: without the binary there is no capability (hello does not
// name it). The scanner runs as a plain process with fixed arguments, never through a shell.
//
// With `scan` ticked in labhud, every image of a ticked container is scanned once (again after a
// day, for the new CVEs of the scanner's database), one at a time; the state then has
// containers.<name>.scan = {critical, high, tool, t}. An update labhud starts on its own can ask
// (hold_critical) that the new image is scanned before it replaces the old one: docker's
// update.go calls Image for that.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/allow"
	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

var (
	First    = 3 * time.Minute  // the first look after the start
	Every    = 10 * time.Minute // how often the ticked containers' images are looked at (cheap)
	Fresh    = 24 * time.Hour   // a result is used this long, then the image is scanned again
	MaxScan  = 15 * time.Minute // one image
	MaxBytes = int64(256 << 20) // a scanner's JSON report
)

// Summary is what the state carries for one image.
type Summary struct {
	Critical int
	High     int
	Tool     string
	T        int64 // when it was scanned (Unix seconds)
}

func (s Summary) Map() map[string]any {
	return map[string]any{"critical": s.Critical, "high": s.High, "tool": s.Tool, "t": s.T}
}

// imageID: what is scanned is always an image id, never a name a registry could move.
var imageID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Scanner struct {
	Tool  string // "trivy" or "grype"
	Path  string // its binary
	Allow *allow.List
	// ImageOf gives the image id a container runs (docker.Docker.ImageOf)
	ImageOf func(ctx context.Context, container string) (string, error)
	Log     func(format string, v ...any)

	// run starts the scanner and gives its standard output (tests replace it)
	run func(ctx context.Context, path string, args ...string) (io.ReadCloser, func() error, error)
	now func() time.Time

	one    sync.Mutex // one scan at a time: a scanner takes a CPU and a lot of memory
	mu     sync.Mutex
	cache  map[string]Summary // image id -> its result
	byName map[string]string  // ticked container -> the image id it runs
}

// New finds trivy, else grype, on the PATH; nil when neither is there.
func New(allowed *allow.List, imageOf func(context.Context, string) (string, error)) *Scanner {
	for _, tool := range []string{"trivy", "grype"} {
		if p, err := exec.LookPath(tool); err == nil {
			return &Scanner{Tool: tool, Path: p, Allow: allowed, ImageOf: imageOf}
		}
	}
	return nil
}

func (s *Scanner) Name() string { return "scan" }

func (s *Scanner) Do(ctx context.Context, verb, target string) error { return caps.ErrNoVerb }

func (s *Scanner) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Scanner) logf(format string, v ...any) {
	if s.Log != nil {
		s.Log(format, v...)
	}
}

func (s *Scanner) on() bool { return s.Allow != nil && s.Allow.Has("scan") }

// Fill adds each ticked container's last result, while `scan` is ticked.
func (s *Scanner) Fill(ctx context.Context, st *proto.State) {
	if !s.on() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, e := range st.Containers {
		if id, ok := s.byName[name]; ok {
			if sum, ok := s.cache[id]; ok {
				e["scan"] = sum.Map()
			}
		}
	}
}

// Watch looks at the ticked containers' images after First and then every Every, and scans the
// ones without a fresh result, until ctx ends.
func (s *Scanner) Watch(ctx context.Context) {
	t := time.NewTimer(First)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.Round(ctx)
		t.Reset(Every)
	}
}

// Round is one look: which image each ticked container runs, and a scan of each that needs one.
func (s *Scanner) Round(ctx context.Context) {
	if !s.on() || s.ImageOf == nil {
		return
	}
	names := map[string]string{}
	for _, name := range s.Allow.Targets("docker") {
		if name == allow.PruneTarget {
			continue
		}
		if id, err := s.ImageOf(ctx, name); err == nil && imageID.MatchString(id) {
			names[name] = id
		}
	}
	s.mu.Lock()
	s.byName = names
	s.mu.Unlock()
	done := map[string]bool{}
	for name, id := range names {
		if done[id] {
			continue
		}
		done[id] = true
		if _, err := s.Image(ctx, id); err != nil {
			s.logf("scan of %s (%s) failed: %v", name, short(id), err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// Image gives the image's summary: the cached one while it is fresh, else a new scan.
func (s *Scanner) Image(ctx context.Context, id string) (Summary, error) {
	if !imageID.MatchString(id) {
		return Summary{}, fmt.Errorf("not an image id: %q", id)
	}
	s.one.Lock()
	defer s.one.Unlock()
	s.mu.Lock()
	sum, ok := s.cache[id]
	s.mu.Unlock()
	if ok && s.clock().Sub(time.Unix(sum.T, 0)) < Fresh {
		return sum, nil
	}
	cctx, cancel := context.WithTimeout(ctx, MaxScan)
	defer cancel()
	sum, err := s.scan(cctx, id)
	if err != nil {
		return Summary{}, err
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]Summary{}
	}
	for k, v := range s.cache { // results of images nothing runs any more go after a while
		if s.clock().Sub(time.Unix(v.T, 0)) > 2*Fresh {
			delete(s.cache, k)
		}
	}
	s.cache[id] = sum
	s.mu.Unlock()
	return sum, nil
}

// Args are the scanner's arguments for one image id (fixed: the id is checked before).
func Args(tool, id string) []string {
	if tool == "grype" {
		return []string{"docker:" + id, "-o", "json", "-q"}
	}
	return []string{"image", "--quiet", "--format", "json", "--scanners", "vuln", "--timeout", "15m", id}
}

func (s *Scanner) scan(ctx context.Context, id string) (Summary, error) {
	run := s.run
	if run == nil {
		run = start
	}
	out, wait, err := run(ctx, s.Path, Args(s.Tool, id)...)
	if err != nil {
		return Summary{}, err
	}
	var sum Summary
	rd := io.LimitReader(out, MaxBytes)
	if s.Tool == "grype" {
		sum, err = ParseGrype(rd)
	} else {
		sum, err = ParseTrivy(rd)
	}
	io.Copy(io.Discard, rd) // the rest, so the process is not stuck on a full pipe
	out.Close()
	if werr := wait(); werr != nil {
		return Summary{}, werr
	}
	if err != nil {
		return Summary{}, fmt.Errorf("%s's report: %w", s.Tool, err)
	}
	sum.Tool, sum.T = s.Tool, s.clock().Unix()
	return sum, nil
}

// start runs the binary with its arguments; wait gives its end, with the last of stderr on failure.
func start(ctx context.Context, path string, args ...string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- trivy/grype from the PATH, fixed arguments
	var stderr bytes.Buffer
	cmd.Stderr = &limited{b: &stderr, n: 4 << 10}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, func() error {
		if err := cmd.Wait(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
				msg = msg[i+1:]
			}
			if len(msg) > 160 {
				msg = msg[:160]
			}
			if msg != "" {
				return fmt.Errorf("%s: %w: %s", path, err, msg)
			}
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	}, nil
}

// limited keeps the first n bytes written to it and drops the rest.
type limited struct {
	b *bytes.Buffer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// count adds one finding, once per (CVE, package).
func count(sum *Summary, seen map[string]bool, id, pkg, severity string) {
	key := id + "\x00" + pkg
	if id == "" || seen[key] {
		return
	}
	seen[key] = true
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		sum.Critical++
	case "HIGH":
		sum.High++
	}
}

// ParseTrivy reads `trivy image --format json`.
func ParseTrivy(r io.Reader) (Summary, error) {
	var rep struct {
		SchemaVersion int
		Results       []struct {
			Vulnerabilities []struct {
				VulnerabilityID string
				PkgName         string
				Severity        string
			}
		}
	}
	if err := json.NewDecoder(r).Decode(&rep); err != nil || rep.SchemaVersion == 0 {
		return Summary{}, errors.New("not trivy's JSON")
	}
	var sum Summary
	seen := map[string]bool{}
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			count(&sum, seen, v.VulnerabilityID, v.PkgName, v.Severity)
		}
	}
	return sum, nil
}

// ParseGrype reads `grype -o json`.
func ParseGrype(r io.Reader) (Summary, error) {
	var rep struct {
		Matches *[]struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"vulnerability"`
			Artifact struct {
				Name string `json:"name"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.NewDecoder(r).Decode(&rep); err != nil || rep.Matches == nil {
		return Summary{}, errors.New("not grype's JSON")
	}
	var sum Summary
	seen := map[string]bool{}
	for _, m := range *rep.Matches {
		count(&sum, seen, m.Vulnerability.ID, m.Artifact.Name, m.Vulnerability.Severity)
	}
	return sum, nil
}

func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
