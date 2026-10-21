package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

// What the engine's events say about a ticked container, for labhud's timeline: it stopped by
// itself with an error, it ran out of memory, or it keeps doing that. A stop asked for (by labhud,
// `docker stop`, compose) comes with a "kill" first and is left out, and so is an update's.
const (
	// KillWindow: a die this soon after a kill was asked for.
	KillWindow = 30 * time.Second
	// LoopCrashes in LoopWindow is a restart loop: said once, then quiet for LoopQuiet.
	LoopCrashes = 3
	LoopWindow  = 10 * time.Minute
	LoopQuiet   = 30 * time.Minute
	// OOMWindow: the die that follows an oom is the same story.
	OOMWindow = 5 * time.Second
)

type engineEvent struct {
	Type   string
	Action string
	Actor  struct{ Attributes map[string]string }
	Time   int64
}

// crashes keeps, per container, what Events needs to tell a crash from a stop.
type crashes struct {
	mu     sync.Mutex
	killed map[string]time.Time
	oom    map[string]time.Time
	died   map[string][]time.Time
	quiet  map[string]time.Time
}

// see turns one engine event into what labhud is told, if anything.
func (c *crashes) see(name, action, exit string, now time.Time) *proto.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.killed == nil {
		c.killed, c.oom, c.died, c.quiet = map[string]time.Time{}, map[string]time.Time{}, map[string][]time.Time{}, map[string]time.Time{}
	}
	ev := &proto.Event{Cap: "docker", Target: name, Bad: true}
	switch action {
	case "kill":
		c.killed[name] = now
		return nil
	case "oom":
		c.oom[name] = now
		ev.Kind, ev.Text = "oom", name+" ran out of memory"
	case "die":
		if now.Sub(c.killed[name]) < KillWindow || exit == "0" || exit == "" {
			return nil
		}
		if now.Sub(c.oom[name]) < OOMWindow {
			return nil
		}
		ev.Kind, ev.Text = "crash", fmt.Sprintf("%s stopped by itself (exit code %s)", name, exit)
	default:
		return nil
	}
	recent := slices.DeleteFunc(append(c.died[name], now), func(t time.Time) bool { return now.Sub(t) > LoopWindow })
	c.died[name] = recent
	if now.Before(c.quiet[name]) {
		return nil
	}
	if len(recent) >= LoopCrashes {
		c.quiet[name] = now.Add(LoopQuiet)
		ev.Kind, ev.Text = "loop", fmt.Sprintf("%s keeps stopping: %d times in %d minutes", name, len(recent), int(LoopWindow.Minutes()))
	}
	return ev
}

// Events follows the engine's container events until ctx ends, again after a lost stream.
func (d *Docker) Events(ctx context.Context) {
	wait := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		d.follow(ctx)
		if time.Since(start) > time.Minute {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
		wait = min(2*wait, time.Minute)
	}
}

func (d *Docker) follow(ctx context.Context) {
	filters := url.QueryEscape(`{"type":["container"],"event":["die","oom","kill"]}`)
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/events?filters="+filters, nil)
	if err != nil {
		return
	}
	r, err := d.c.Do(req)
	if err != nil {
		return
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		return
	}
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e engineEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		d.seen(e, time.Now())
	}
}

func (d *Docker) seen(e engineEvent, now time.Time) {
	name := e.Actor.Attributes["name"]
	if name == "" || strings.HasSuffix(name, "-labhud-old") || d.Allow == nil ||
		!slices.Contains(d.Allow.Targets("docker"), name) {
		return
	}
	d.mu.Lock()
	busy := d.busy[name]
	d.mu.Unlock()
	if busy { // its update stops it, and its new one may not stay up: the update says so
		return
	}
	if ev := d.crash.see(name, strings.SplitN(e.Action, ":", 2)[0], e.Actor.Attributes["exitCode"], now); ev != nil {
		d.send1(*ev)
	}
}
