package smb2

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInitiatorFor(t *testing.T) {
	t.Run("ntlm", func(t *testing.T) {
		orig := &NTLMInitiator{User: "u", Password: "p", Domain: "D", TargetSPN: "cifs/origin"}
		got, ok := initiatorFor(orig, "target.example").(*NTLMInitiator)
		if !ok || got == orig {
			t.Fatalf("want a new *NTLMInitiator, got %T (same=%v)", got, got == orig)
		}
		if got.User != "u" || got.Password != "p" || got.Domain != "D" {
			t.Errorf("credentials not copied: %+v", got)
		}
		if got.TargetSPN != "cifs/target.example" {
			t.Errorf("TargetSPN = %q, want cifs/target.example", got.TargetSPN)
		}
		// No SPN set for the origin: none for the target either.
		if spn := initiatorFor(&NTLMInitiator{User: "u"}, "t").(*NTLMInitiator).TargetSPN; spn != "" {
			t.Errorf("TargetSPN = %q, want empty", spn)
		}
	})
	t.Run("kerberos", func(t *testing.T) {
		orig := &Krb5Initiator{TargetSPN: "cifs/origin"}
		got, ok := initiatorFor(orig, "target").(*Krb5Initiator)
		if !ok || got == orig {
			t.Fatalf("want a new *Krb5Initiator, got %T (same=%v)", got, got == orig)
		}
		if got.TargetSPN != "cifs/target" {
			t.Errorf("TargetSPN = %q, want cifs/target", got.TargetSPN)
		}
	})
}

// TestBackingConns_SingleDial: concurrent callers needing the same server
// must share one dial, and a failed dial must be retried by the next caller.
func TestBackingConns_SingleDial(t *testing.T) {
	var dials atomic.Int32
	release := make(chan struct{})
	d := Dialer{
		Initiator: &NTLMInitiator{},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			<-release
			return nil, errors.New("unreachable")
		},
	}
	b := newBackingConns()

	var wg sync.WaitGroup
	leases := make([]dfsLeases, 8)
	for i := range leases {
		leases[i] = make(dfsLeases)
		wg.Go(func() {
			if _, err := b.session(context.Background(), "srv", d, leases[i]); err == nil {
				t.Error("want the dial error")
			}
		})
	}
	time.Sleep(50 * time.Millisecond) // let them all queue behind the dial
	close(release)
	wg.Wait()
	if n := dials.Load(); n != 1 {
		t.Errorf("dialed %d times, want 1", n)
	}

	// The failed dial is not reused.
	if _, err := b.session(context.Background(), "srv", d, make(dfsLeases)); err == nil {
		t.Error("want the dial error")
	}
	if n := dials.Load(); n != 2 {
		t.Errorf("dialed %d times after a failure, want 2", n)
	}

	for _, l := range leases {
		b.release(l)
		if len(l) != 0 {
			t.Errorf("leases not cleared: %d", len(l))
		}
	}
}

// TestBackingConns_Leases: an entry stays while leased and goes with the
// last lease.
func TestBackingConns_Leases(t *testing.T) {
	d := Dialer{
		Initiator: &NTLMInitiator{},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unreachable")
		},
	}
	b := newBackingConns()
	l1, l2 := make(dfsLeases), make(dfsLeases)
	_, _ = b.session(context.Background(), "srv", d, l1)
	// Same lease set twice counts once.
	_, _ = b.session(context.Background(), "srv", d, l1)
	bc := b.conns["srv"]
	if bc == nil || bc.refs != 1 {
		t.Fatalf("refs = %v, want 1", bc)
	}
	// A second resolver redials (the first dial failed) on a new entry.
	_, _ = b.session(context.Background(), "SRV", d, l2)
	if b.conns["srv"] == bc {
		t.Fatal("failed entry was reused")
	}
	b.release(l2)
	if _, ok := b.conns["srv"]; ok {
		t.Error("entry kept after its last lease was released")
	}
	b.release(l1)
	if bc.refs != 0 {
		t.Errorf("old entry refs = %d, want 0", bc.refs)
	}
}
