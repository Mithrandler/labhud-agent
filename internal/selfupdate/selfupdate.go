// Package selfupdate replaces the agent's own binary with a newer release, when labhud asks.
//
// labhud can command an agent, but it must not be able to make it run anything: the agent runs as
// root. So labhud only names a version and its SHA-256, and the agent decides the rest itself:
//
//   - it downloads only from its own releases (Releases, compiled in; LABHUD_AGENT_RELEASES in the
//     host's own config can point elsewhere, labhud cannot);
//   - the binary must match both the SHA-256 labhud sent and the one in that release's SHA256SUMS;
//   - only a newer version than its own: labhud cannot take it back to an older release with a
//     known fault;
//   - not in a container: there the image is the agent, and the image updater (or a new
//     `docker run`) updates it.
//
// Then the file replaces the running binary (a rename in its folder, so a crash halfway leaves
// the old one) and the process execs it: same PID, so systemd sees nothing but a new version.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Releases is where the agent's builds are published: <Releases>/v<version>/labhud-agent-linux-<arch>.
const Releases = "https://github.com/Mithrandler/labhud-agent/releases/download"

const (
	maxSums   = 64 << 10
	maxBinary = 64 << 20
)

var (
	versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	hexRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Updater holds what an update needs from the agent around it.
type Updater struct {
	Own         string // the running version
	Releases    string // where to download from ("" = Releases)
	InContainer bool
	Exe         string // the running binary ("" = os.Executable)
	Client      *http.Client
}

// Newer: is v a later release than own? A dev build ("0.1.0-dev.a0e2b4d") is older than its release.
func Newer(v, own string) bool {
	a, okA := parts(v)
	b, okB := parts(own)
	if !okA || !versionRe.MatchString(v) { // only a release is ever a target
		return false
	}
	if !okB {
		return true // "dev", or anything that is not a release: any release is newer
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return strings.Contains(own, "-") // 0.1.0 over 0.1.0-dev.x
}

func parts(v string) ([3]int, bool) {
	var out [3]int
	core, _, _ := strings.Cut(v, "-")
	if !versionRe.MatchString(core) {
		return out, false
	}
	for i, p := range strings.Split(core, ".") {
		out[i], _ = strconv.Atoi(p)
	}
	return out, true
}

// Asset is the build's file name for this machine.
func Asset() string { return "labhud-agent-linux-" + runtime.GOARCH }

// Fetch downloads and checks version, and puts it in place of the running binary. It returns the
// path to exec. Nothing is replaced unless every check passed.
func (u *Updater) Fetch(ctx context.Context, version, want string) (string, error) {
	switch {
	case u.InContainer:
		return "", errors.New("a container is updated by its image, not by itself")
	case !versionRe.MatchString(version):
		return "", fmt.Errorf("not a release version: %q", version)
	case !hexRe.MatchString(want):
		return "", errors.New("not a SHA-256")
	case !Newer(version, u.Own):
		return "", fmt.Errorf("%s is not newer than %s", version, u.Own)
	}
	base := strings.TrimRight(u.Releases, "/")
	if base == "" {
		base = Releases
	}
	if !strings.HasPrefix(base, "https://") {
		return "", errors.New("releases must be an https address")
	}
	dir := base + "/v" + version + "/"
	sums, err := u.get(ctx, dir+"SHA256SUMS", maxSums)
	if err != nil {
		return "", fmt.Errorf("SHA256SUMS: %w", err)
	}
	listed := sumFor(string(sums), Asset())
	if listed == "" {
		return "", fmt.Errorf("SHA256SUMS of %s has no %s", version, Asset())
	}
	if listed != want {
		return "", errors.New("labhud's SHA-256 is not the release's: not updated")
	}
	exe := u.Exe
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return "", err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return "", err
		}
	}
	bin, err := u.get(ctx, dir+Asset(), maxBinary)
	if err != nil {
		return "", fmt.Errorf("%s: %w", Asset(), err)
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return "", errors.New("the download does not match its SHA-256: not updated")
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".labhud-agent-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // gone after the rename; left over only on an error
	if _, err = tmp.Write(bin); err == nil {
		err = tmp.Chmod(0o755)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return "", err
	}
	return exe, nil
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	c := u.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("too large")
	}
	return b, nil
}

// sumFor finds the file's line in a SHA256SUMS ("<hex>  <name>", or "<hex> *<name>").
func sumFor(sums, name string) string {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && hexRe.MatchString(strings.ToLower(f[0])) {
			return strings.ToLower(f[0])
		}
	}
	return ""
}
