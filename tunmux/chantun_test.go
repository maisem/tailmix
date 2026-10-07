package tunmux

import (
	"bytes"
	"io"
	"testing"
	"time"

	wgtun "github.com/tailscale/wireguard-go/tun"
)

func TestPacketReleaseInvalidatesAllHandles(t *testing.T) {
	pool := newPacketPool(16, chanTUNMTU)
	packet := pool.copy([]byte("packet"))
	stale := packet
	packet.Release()
	assertPanics(t, func() { stale.Bytes() })
	assertPanics(t, func() { stale.Release() })
}

func TestChanTUNReadReleasesTransferredPacket(t *testing.T) {
	tun := NewChanTUN("test")
	packet := tun.pool.copy([]byte("outbound"))
	stale := packet
	if err := tun.injectOutboundPacket(packet); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	packets := make([]wgtun.ReadPacket, 1)
	n, err := tun.Read(buf, packets)
	if err != nil || n != 1 || !bytes.Equal(buf[packets[0].Offset:packets[0].Offset+packets[0].Size], []byte("outbound")) {
		t.Fatalf("Read = (%d, %v, %q)", n, err, buf[packets[0].Offset:packets[0].Offset+packets[0].Size])
	}
	assertPanics(t, func() { stale.Bytes() })
}

func TestChanTUNReadDrainsQueuedBatchInFIFOOrder(t *testing.T) {
	tun := NewChanTUN("test")
	if got := tun.BatchSize(); got != 128 {
		t.Fatalf("BatchSize = %d, want 128", got)
	}

	stale := make([]Packet, 3)
	for i, payload := range [][]byte{[]byte("first"), []byte("second"), []byte("third")} {
		packet := tun.pool.copy(payload)
		stale[i] = packet
		if err := tun.injectOutboundPacket(packet); err != nil {
			t.Fatal(err)
		}
	}

	slab := make([]byte, 512)
	packets := make([]wgtun.ReadPacket, 4)
	done := make(chan struct{})
	var n int
	var err error
	go func() {
		n, err = tun.Read(slab, packets)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Read waited for an unqueued packet")
	}
	if err != nil || n != 3 {
		t.Fatalf("Read = (%d, %v), want (3, nil)", n, err)
	}
	for i, want := range []string{"first", "second", "third"} {
		if got := string(slab[packets[i].Offset : packets[i].Offset+packets[i].Size]); got != want {
			t.Fatalf("packet %d = %q, want %q", i, got, want)
		}
		packet := stale[i]
		assertPanics(t, func() { packet.Bytes() })
	}
}

func TestChanTUNReadRespectsCallerBatchCapacity(t *testing.T) {
	tun := NewChanTUN("test")
	for _, payload := range [][]byte{[]byte("first"), []byte("second"), []byte("third")} {
		if err := tun.InjectOutbound(payload); err != nil {
			t.Fatal(err)
		}
	}

	slab := make([]byte, 512)
	packets := make([]wgtun.ReadPacket, 2)
	if n, err := tun.Read(slab, packets); err != nil || n != 2 {
		t.Fatalf("first Read = (%d, %v), want (2, nil)", n, err)
	}
	if got := []string{string(slab[packets[0].Offset : packets[0].Offset+packets[0].Size]), string(slab[packets[1].Offset : packets[1].Offset+packets[1].Size])}; got[0] != "first" || got[1] != "second" {
		t.Fatalf("first Read packets = %q", got)
	}
	if n, err := tun.Read(slab, packets); err != nil || n != 1 || string(slab[packets[0].Offset:packets[0].Offset+packets[0].Size]) != "third" {
		t.Fatalf("second Read = (%d, %v, %q), want third", n, err, slab[packets[0].Offset:packets[0].Offset+packets[0].Size])
	}
}

func TestChanTUNReadReportsSlabOverflowWithoutTruncating(t *testing.T) {
	tun := NewChanTUN("test")
	t.Cleanup(func() { tun.Close() })
	stale := make([]Packet, 3)
	for i, payload := range []string{"first", "too large", "last"} {
		packet := tun.pool.copy([]byte(payload))
		stale[i] = packet
		if err := tun.injectOutboundPacket(packet); err != nil {
			t.Fatal(err)
		}
	}
	slab := bytes.Repeat([]byte{0xff}, 2*wgtun.ReadPacketSpacing+len("first"))
	packets := make([]wgtun.ReadPacket, tun.BatchSize())
	n, err := tun.Read(slab, packets)
	if n != 1 || err != wgtun.ErrTooManySegments {
		t.Fatalf("Read = (%d, %v), want (1, ErrTooManySegments)", n, err)
	}
	pkt := packets[0]
	if pkt.Offset != wgtun.ReadPacketSpacing || string(slab[pkt.Offset:pkt.Offset+pkt.Size]) != "first" {
		t.Fatalf("Read packet = %+v, slab = %v", pkt, slab)
	}
	if !bytes.Equal(slab[:pkt.Offset], bytes.Repeat([]byte{0xff}, wgtun.ReadPacketSpacing)) ||
		!bytes.Equal(slab[pkt.Offset+pkt.Size:], bytes.Repeat([]byte{0xff}, wgtun.ReadPacketSpacing)) {
		t.Fatal("Read overwrote packet spacing")
	}
	assertPanics(t, func() { stale[0].Bytes() })
	assertPanics(t, func() { stale[1].Bytes() })
	n, err = tun.Read(slab, packets)
	pkt = packets[0]
	if n != 1 || err != nil || string(slab[pkt.Offset:pkt.Offset+pkt.Size]) != "last" {
		t.Fatalf("Read after overflow = (%d, %v), want last", n, err)
	}
	assertPanics(t, func() { stale[2].Bytes() })
}

func TestChanTUNWriteCopiesBorrowedBatchInFIFOOrder(t *testing.T) {
	tun := NewChanTUN("test")
	borrowed := [][]byte{[]byte("--first"), []byte("--second"), []byte("--third")}
	if n, err := tun.Write(borrowed, 2); err != nil || n != len(borrowed) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(borrowed))
	}
	for i := range borrowed {
		borrowed[i][2] = 'X'
	}
	for i, want := range []string{"first", "second", "third"} {
		packet := <-tun.Inbound()
		if got := string(packet.Bytes()); got != want {
			packet.Release()
			t.Fatalf("packet %d = %q, want %q", i, got, want)
		}
		packet.Release()
	}
}

func TestChanTUNWriteCopiesBorrowedBuffer(t *testing.T) {
	tun := NewChanTUN("test")
	borrowed := []byte("inbound")
	n, err := tun.Write([][]byte{borrowed}, 0)
	if err != nil || n != 1 {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	borrowed[0] = 'X'
	packet := <-tun.Inbound()
	if got := string(packet.Bytes()); got != "inbound" {
		packet.Release()
		t.Fatalf("queued packet = %q", got)
	}
	packet.Release()
}

func TestChanTUNWriteDropsPerPacketWhenInboundQueueIsFull(t *testing.T) {
	tun := NewChanTUN("test")
	for range chanTUNQueueSize {
		if n, err := tun.Write([][]byte{{1}}, 0); err != nil || n != 1 {
			t.Fatalf("fill Write = (%d, %v)", n, err)
		}
	}
	if n, err := tun.Write([][]byte{{2}, {3}}, 0); err != nil || n != 2 {
		t.Fatalf("full Write = (%d, %v), want consumed batch", n, err)
	}
	if got := len(tun.inbound); got != chanTUNQueueSize {
		t.Fatalf("inbound queue length = %d, want %d", got, chanTUNQueueSize)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChanTUNCloseReleasesQueuesAndUnblocksRead(t *testing.T) {
	tun := NewChanTUN("test")
	outbound := tun.pool.copy([]byte("outbound"))
	outboundStale := outbound
	if err := tun.injectOutboundPacket(outbound); err != nil {
		t.Fatal(err)
	}
	inbound := tun.pool.copy([]byte("inbound"))
	inboundStale := inbound
	if ok, err := tun.tryInjectInboundPacket(inbound); err != nil || !ok {
		t.Fatalf("inject inbound = (%v, %v)", ok, err)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	assertPanics(t, func() { outboundStale.Bytes() })
	assertPanics(t, func() { inboundStale.Bytes() })

	done := make(chan error, 1)
	go func() {
		_, err := tun.Read(make([]byte, 256), make([]wgtun.ReadPacket, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("Read after Close = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
}

func assertPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("function did not panic")
		}
	}()
	f()
}
