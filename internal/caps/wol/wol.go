// Package wol wakes machines on the agent's LAN with a magic packet, and lists the ARP table so
// labhud can offer them as targets.
package wol

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Mithrandler/labhud-agent/internal/caps"
	"github.com/Mithrandler/labhud-agent/internal/proto"
)

type WOL struct {
	Root string
	// Send writes the packet to every address; replaced in tests.
	Send func(ctx context.Context, packet []byte, addrs []string) error
}

func New(root string) *WOL { return &WOL{Root: root, Send: send} }

func (w *WOL) Name() string { return "wol" }

// Neighbours reads the ARP table: complete entries only.
func Neighbours(path string) map[string]map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]map[string]any{}
	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	for sc.Scan() {
		c := strings.Fields(sc.Text())
		if len(c) < 6 || c[2] != "0x2" || c[3] == "00:00:00:00:00:00" {
			continue
		}
		out[strings.ToLower(c[3])] = map[string]any{"ip": c[0], "dev": c[5]}
	}
	return out
}

func (w *WOL) Fill(_ context.Context, st *proto.State) {
	if n := Neighbours(filepath.Join(w.Root, "proc/net/arp")); n != nil {
		st.Neighbours = n
	}
}

// Packet is the magic packet: six 0xFF, then the MAC sixteen times.
func Packet(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return nil, errors.New("not a MAC address")
	}
	p := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		p = append(p, 0xFF)
	}
	for i := 0; i < 16; i++ {
		p = append(p, hw...)
	}
	return p, nil
}

// broadcasts: the limited broadcast and each IPv4 network's own, for hosts with several LANs.
func broadcasts() []string {
	addrs := []string{"255.255.255.255:9"}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagBroadcast == 0 {
			continue
		}
		as, _ := i.Addrs()
		for _, a := range as {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			ip, mask := n.IP.To4(), net.IP(n.Mask).To4()
			if mask == nil {
				continue
			}
			b := make(net.IP, 4)
			for k := range b {
				b[k] = ip[k] | ^mask[k]
			}
			addrs = append(addrs, b.String()+":9")
		}
	}
	return addrs
}

func send(ctx context.Context, packet []byte, addrs []string) error {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return err
	}
	defer pc.Close()
	sent := 0
	var last error
	for _, a := range addrs {
		ua, err := net.ResolveUDPAddr("udp4", a)
		if err == nil {
			_, err = pc.WriteTo(packet, ua)
		}
		if err != nil {
			last = err
			continue
		}
		sent++
	}
	if sent == 0 {
		return last
	}
	return nil
}

func (w *WOL) Do(ctx context.Context, verb, target string) error {
	if verb != "wake" {
		return caps.ErrNoVerb
	}
	p, err := Packet(target)
	if err != nil {
		return err
	}
	return w.Send(ctx, p, broadcasts())
}
