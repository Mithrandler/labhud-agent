package wol

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mithrandler/labhud-agent/internal/proto"
)

func TestNeighbours(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "proc/net"), 0o755)
	os.WriteFile(filepath.Join(root, "proc/net/arp"), []byte(
		"IP address       HW type     Flags       HW address            Mask     Device\n"+
			"192.0.2.50     0x1         0x2         AA:BB:CC:DD:EE:FF     *        vmbr0\n"+
			"192.0.2.51     0x1         0x0         00:00:00:00:00:00     *        vmbr0\n"+
			"192.0.2.52     0x1         0x2         00:00:00:00:00:00     *        vmbr0\n"), 0o644)
	w := New(root)
	var st proto.State
	w.Fill(context.Background(), &st)
	if len(st.Neighbours) != 1 || st.Neighbours["aa:bb:cc:dd:ee:ff"]["ip"] != "192.0.2.50" {
		t.Errorf("%v", st.Neighbours)
	}
}

func TestPacketAndDo(t *testing.T) {
	var got []byte
	w := &WOL{Send: func(_ context.Context, p []byte, addrs []string) error {
		got = p
		if addrs[0] != "255.255.255.255:9" {
			t.Errorf("addrs %v", addrs)
		}
		return nil
	}}
	if err := w.Do(context.Background(), "wake", "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 102 || !bytes.Equal(got[:6], bytes.Repeat([]byte{0xFF}, 6)) ||
		!bytes.Equal(got[96:], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("packet % x", got)
	}
	if w.Do(context.Background(), "wake", "not-a-mac") == nil {
		t.Error("a bad MAC was sent")
	}
}

func TestSendsForReal(t *testing.T) { // to the loopback: the socket and SO_BROADCAST work
	p, _ := Packet("aa:bb:cc:dd:ee:ff")
	if err := send(context.Background(), p, []string{"127.0.0.1:9"}); err != nil {
		t.Fatal(err)
	}
}
