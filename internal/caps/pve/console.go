package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Mithrandler/labhud-agent/internal/caps"
)

// The console of a guest: Proxmox's own `termproxy` (the text console its web page draws in
// xterm.js) over a websocket, with the same token. An LXC gives its login; a VM only has one
// when it has a serial port (serial0 with socket) and a getty on it. The verb needs VM.Console.
const (
	ConsoleLife = 15 * time.Minute
	ConsoleIdle = 3 * time.Minute
	// pingEvery keeps termproxy from closing a console nobody types in
	pingEvery   = 30 * time.Second
	resizeDelay = 400 * time.Millisecond
	// inputChunk: termproxy takes "0:<length>:<bytes>" messages; a long paste goes in pieces
	inputChunk = 4096
)

func (p *PVE) Streams(verb string) bool { return verb == "console" }

func (p *PVE) Limits(string) (time.Duration, time.Duration) { return ConsoleLife, ConsoleIdle }

type console struct {
	ws     *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex // writes to the websocket
	rest   []byte     // output read together with the greeting
}

func (p *PVE) Open(ctx context.Context, verb, target string, cols, rows int) (caps.Stream, error) {
	if verb != "console" {
		return nil, fmt.Errorf("pve: no stream %q", verb)
	}
	_, _, base, err := p.guest(ctx, target)
	if err != nil {
		return nil, err
	}
	var tp struct {
		Port         any
		Ticket, User string
	}
	if err := p.call(ctx, "POST", base+"/termproxy", &tp); err != nil {
		return nil, consoleErr(err)
	}
	if tp.Ticket == "" || tp.User == "" {
		return nil, errors.New("proxmox: no console came back")
	}
	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, err
	}
	u.Scheme = map[string]string{"http": "ws", "https": "wss"}[u.Scheme]
	q := url.Values{"port": {fmt.Sprint(tp.Port)}, "vncticket": {tp.Ticket}}
	u.Path += "/api2/json" + base + "/vncwebsocket"
	u.RawQuery = q.Encode()
	dctx, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	ws, _, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: p.Client.Transport},
		HTTPHeader:   http.Header{"Authorization": {"PVEAPIToken=" + p.Token}},
		Subprotocols: []string{"binary"},
	})
	if err != nil {
		return nil, fmt.Errorf("proxmox: the console did not open: %w", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	c := &console{ws: ws, ctx: cctx, cancel: cancel}
	if err := ws.Write(dctx, websocket.MessageBinary, []byte(tp.User+":"+tp.Ticket+"\n")); err != nil {
		c.Close()
		return nil, err
	}
	_, hello, err := ws.Read(dctx)
	if err != nil || !strings.HasPrefix(string(hello), "OK") {
		c.Close()
		return nil, errors.New("proxmox: the console refused the ticket")
	}
	c.rest = hello[2:]
	if cols > 0 && rows > 0 {
		// the size goes a moment after the greeting: the program on the other end redraws its login when it
		// is resized, and one resized before it listens shows nothing until a key is pressed
		time.AfterFunc(resizeDelay, func() { c.Resize(cols, rows) })
	}
	go func() {
		t := time.NewTicker(pingEvery)
		defer t.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
				c.send([]byte("2"))
			}
		}
	}()
	return c, nil
}

// consoleErr says what a refused termproxy usually means.
func consoleErr(err error) error {
	if strings.Contains(err.Error(), "403") {
		return errors.New("proxmox: the token lacks VM.Console (install-agent.sh --pve-console)")
	}
	return err
}

func (c *console) send(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageBinary, b)
}

func (c *console) Read(p []byte) (int, error) {
	if len(c.rest) > 0 {
		n := copy(p, c.rest)
		c.rest = c.rest[n:]
		return n, nil
	}
	_, msg, err := c.ws.Read(c.ctx)
	if err != nil {
		return 0, err
	}
	n := copy(p, msg)
	c.rest = msg[n:]
	return n, nil
}

func (c *console) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		part := p[done:min(len(p), done+inputChunk)]
		if err := c.send([]byte(fmt.Sprintf("0:%d:%s", len(part), part))); err != nil {
			return done, err
		}
		done += len(part)
	}
	return done, nil
}

func (c *console) Resize(cols, rows int) error {
	return c.send([]byte(fmt.Sprintf("1:%d:%d:", cols, rows)))
}

func (c *console) Close() error {
	c.cancel()
	return c.ws.Close(websocket.StatusNormalClosure, "")
}
