package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mithrandler/labhud-agent/internal/allow"
)

// LogLines is how many of the last lines `logs` asks for.
const LogLines = 200

func (d *Docker) Reads(verb string) bool {
	return verb == "logs" || verb == "inspect" || verb == "stats" || allow.HostVerb(verb)
}

// Read gives a container's last lines (stdout and stderr, in order), without colour codes; or,
// for prune, what cleaning the unused images freed.
func (d *Docker) Read(ctx context.Context, verb, target string) (string, error) {
	if allow.HostVerb(verb) {
		return d.host(ctx, verb, target)
	}
	if verb == "inspect" {
		return d.inspect(ctx, target)
	}
	if verb == "stats" {
		return d.statsNow(ctx, target)
	}
	if verb != "logs" {
		return "", fmt.Errorf("docker: no read verb %q", verb)
	}
	var info struct{ Config struct{ Tty bool } }
	if err := d.call(ctx, "GET", "/containers/"+url.PathEscape(target)+"/json", &info); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("http://docker/containers/%s/logs?stdout=1&stderr=1&tail=%d", url.PathEscape(target), LogLines), nil)
	if err != nil {
		return "", err
	}
	r, err := d.c.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.StatusCode >= 300 {
		return "", fmt.Errorf("docker: HTTP %d", r.StatusCode)
	}
	if !info.Config.Tty {
		body = demux(body)
	}
	return clean(body), nil
}

// demux joins the frames of a non-TTY log stream: an 8-byte header (stream, 0, 0, 0, size)
// before each piece. A stream that does not look framed is kept as it is.
func demux(b []byte) []byte {
	var out bytes.Buffer
	for len(b) >= 8 {
		if b[0] > 2 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
			out.Write(b)
			return out.Bytes()
		}
		n := int(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
		if n > len(b) {
			n = len(b)
		}
		out.Write(b[:n])
		b = b[n:]
	}
	out.Write(b)
	return out.Bytes()
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)

// clean: colour and cursor codes out, \r\n as \n, invalid UTF-8 replaced, other control
// characters (but tabs) dropped.
func clean(b []byte) string {
	s := ansi.ReplaceAllString(string(b), "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' || r == 127 {
			return -1
		}
		return r
	}, s)
}

// PruneTarget is the one target of prune: the host's images, not one container's.
const PruneTarget = allow.PruneTarget

// PruneAge: an image unused for less than this stays (an update's old image, for a while).
const PruneAge = "24h"

// prune removes the images no container uses (stopped ones count as using theirs), unused for
// PruneAge at least, as `docker image prune -a --filter until=24h`.
func (d *Docker) prune(ctx context.Context, target string) (string, error) {
	if target != PruneTarget {
		return "", fmt.Errorf("docker: prune takes %q", PruneTarget)
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	var out struct {
		ImagesDeleted  []struct{ Deleted string }
		SpaceReclaimed uint64
	}
	filters := url.QueryEscape(`{"dangling":["false"],"until":["` + PruneAge + `"]}`)
	if err := d.call(ctx, "POST", "/images/prune?filters="+filters, &out); err != nil {
		return "", err
	}
	n := 0
	for _, i := range out.ImagesDeleted {
		if i.Deleted != "" {
			n++
		}
	}
	return fmt.Sprintf("freed %s (%d image layers)", size(out.SpaceReclaimed), n), nil
}

func size(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d KB", b>>10)
}
