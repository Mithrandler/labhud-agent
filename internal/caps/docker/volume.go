package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mithrandler/labhud-agent/internal/allow"
)

// Looking inside a volume, read only, for the volumes ticked for it. The engine gives a path of a
// container's file system as a tar stream, also for a container that never started: a container
// is made (not started, no network, the volume mounted read only), asked, and removed. Nothing in
// the volume is run, and nothing is written to it.
const (
	listMax    = 300   // entries of one directory that are answered
	scanMax    = 20000 // tar headers read before the listing stops (a big tree is not walked to its end)
	scanTime   = 12 * time.Second
	readMax    = 64 << 10 // bytes of a file that are answered
	mountPoint = "/v"
)

// Entry is one thing in a directory.
type Entry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Link  bool   `json:"link,omitempty"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

type Listing struct {
	Path      string  `json:"path"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated,omitempty"`
}

type FileText struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Text      string `json:"text,omitempty"`
	Binary    bool   `json:"binary,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Masked    bool   `json:"masked,omitempty"`
}

// withVolume runs fn with a helper container that has the volume mounted read only.
func (d *Docker) withVolume(ctx context.Context, volume string, fn func(id string) error) error {
	var images []struct {
		RepoTags []string
		Size     int64
	}
	if err := d.call(ctx, "GET", "/images/json", &images); err != nil {
		return err
	}
	pick, best := "", int64(-1)
	for _, i := range images { // the smallest image with a name: nothing of it runs
		for _, t := range i.RepoTags {
			if t != "<none>:<none>" && (best < 0 || i.Size < best) {
				pick, best = t, i.Size
			}
		}
	}
	if pick == "" {
		return errors.New("docker: no image on this host to open a volume with")
	}
	suffix := make([]byte, 6)
	rand.Read(suffix)
	body := map[string]any{
		"Image": pick, "Cmd": []string{"true"}, "NetworkDisabled": true,
		"Labels":     map[string]string{"labhud.helper": "volume"},
		"HostConfig": map[string]any{"Binds": []string{volume + ":" + mountPoint + ":ro"}, "NetworkMode": "none"},
	}
	var made struct{ Id string }
	if err := d.send(ctx, "POST", "/containers/create?name=labhud-vol-"+hex.EncodeToString(suffix), body, &made); err != nil {
		return err
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		d.call(rctx, "DELETE", "/containers/"+made.Id+"?force=1&v=0", nil)
	}()
	return fn(made.Id)
}

// archive opens the tar stream of a path inside the mounted volume.
func (d *Docker) archive(ctx context.Context, id, inside string) (io.ReadCloser, error) {
	where := mountPoint + inside
	if inside == "/" {
		where = mountPoint
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/containers/"+id+"/archive?path="+url.QueryEscape(where), nil)
	if err != nil {
		return nil, err
	}
	r, err := d.c.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode >= 300 {
		defer r.Body.Close()
		var e struct{ Message string }
		json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&e)
		if r.StatusCode == 404 {
			return nil, errors.New("docker: no such path in the volume")
		}
		if e.Message == "" {
			e.Message = fmt.Sprintf("HTTP %d", r.StatusCode)
		}
		return nil, fmt.Errorf("docker: %s", e.Message)
	}
	return r.Body, nil
}

func (d *Docker) volumeLs(ctx context.Context, volume, arg string) (string, error) {
	dir, err := allow.CleanPath(arg)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, scanTime+10*time.Second)
	defer cancel()
	var out Listing
	err = d.withVolume(ctx, volume, func(id string) error {
		body, err := d.archive(ctx, id, dir)
		if err != nil {
			return err
		}
		defer body.Close()
		out = listTar(body, dir, time.Now().Add(scanTime))
		return nil
	})
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// listTar reads the headers of the tar of a directory and keeps the direct children. The tar holds
// the whole tree, depth first: it stops after scanMax headers or at the deadline and says so.
func listTar(r io.Reader, dir string, deadline time.Time) Listing {
	out := Listing{Path: dir, Entries: []Entry{}}
	root := path.Base(dir) // the archive's names start with the directory's own name
	if dir == "/" {
		root = path.Base(mountPoint)
	}
	tr := tar.NewReader(r)
	seen := map[string]bool{}
	for n := 0; n < scanMax; n++ {
		if time.Now().After(deadline) {
			out.Truncated = true
			break
		}
		h, err := tr.Next()
		if err != nil {
			break
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path.Clean(h.Name), root), "/")
		if rel == "" || rel == "." {
			continue
		}
		first, rest, deeper := strings.Cut(rel, "/")
		if first == "" || seen[first] {
			continue
		}
		e := Entry{Name: first, Dir: deeper || h.Typeflag == tar.TypeDir, Link: h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink}
		if !deeper || rest == "" {
			e.Size, e.MTime = h.Size, h.ModTime.Unix()
		}
		if utf8.ValidString(first) {
			seen[first] = true
			if len(out.Entries) >= listMax {
				out.Truncated = true
				continue
			}
			out.Entries = append(out.Entries, e)
		}
	}
	sort.SliceStable(out.Entries, func(a, b int) bool {
		x, y := out.Entries[a], out.Entries[b]
		if x.Dir != y.Dir {
			return x.Dir
		}
		return strings.ToLower(x.Name) < strings.ToLower(y.Name)
	})
	return out
}

// secretFile: a file that probably holds a secret. A dotenv file shows its names and hides the values;
// the others show nothing of their content.
func secretFile(name string) (secret, dotenv bool) {
	n := strings.ToLower(path.Base(name))
	if n == ".env" || strings.HasSuffix(n, ".env") || strings.HasPrefix(n, ".env.") {
		return true, true
	}
	for _, w := range []string{"key", "secret", "token", "passw", "credential", "id_rsa", "id_ed25519", "id_ecdsa"} {
		if strings.Contains(n, w) {
			return true, false
		}
	}
	return strings.HasSuffix(n, ".pem") || strings.HasSuffix(n, ".p12") || strings.HasSuffix(n, ".pfx") || strings.HasPrefix(n, "id_"), false
}

func maskEnv(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if k, _, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			lines[i] = k + "=••••"
		}
	}
	return strings.Join(lines, "\n")
}

func (d *Docker) volumeRead(ctx context.Context, volume, arg string) (string, error) {
	file, err := allow.CleanPath(arg)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out := FileText{Path: file}
	err = d.withVolume(ctx, volume, func(id string) error {
		body, err := d.archive(ctx, id, file)
		if err != nil {
			return err
		}
		defer body.Close()
		tr := tar.NewReader(body)
		h, err := tr.Next()
		if err != nil {
			return errors.New("docker: nothing to read there")
		}
		if h.Typeflag != tar.TypeReg {
			return errors.New("docker: not a regular file")
		}
		out.Size = h.Size
		secret, dotenv := secretFile(file)
		if secret && !dotenv {
			out.Masked = true // nothing of its content leaves the host
			return nil
		}
		data, _ := io.ReadAll(io.LimitReader(tr, readMax+1))
		if len(data) > readMax {
			data, out.Truncated = data[:readMax], true
		}
		if out.Truncated { // a character cut in two at the end is not a reason to call it binary
			for k := 0; k < 3 && len(data) > 0 && !utf8.Valid(data); k++ {
				data = data[:len(data)-1]
			}
		}
		if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			out.Binary = true
			return nil
		}
		out.Text = string(data)
		if dotenv {
			out.Text, out.Masked = maskEnv(out.Text), true
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(out)
	return string(b), err
}
