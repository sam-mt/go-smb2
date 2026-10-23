package smb2_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/sam-mt/go-smb2"
)

// A range far past any realistic end of file: the lock is used as a mutex
// between cooperating writers, so it must never overlap data anyone reads or
// writes (Windows enforces byte-range locks on reads and writes).
const lockOffset, lockLength = int64(1) << 62, int64(1)

// secondShare opens fsName over a session of its own, so its opens are a
// different client as far as the server is concerned.
func secondShare(t *testing.T) (*smb2.Session, *smb2.Share) {
	t.Helper()
	c, err := dialer.Dial(context.Background(), fmt.Sprintf("%s:%d", cfg.Transport.Host, cfg.Transport.Port))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Mount(fsName)
	if err != nil {
		_ = c.Logoff()
		t.Fatal(err)
	}
	return c, s
}

func lockTestFile(t *testing.T, name string) string {
	t.Helper()
	p := fmt.Sprintf("testLock-%d-%s", os.Getpid(), name)
	f, err := fs.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = fs.Remove(p) })
	return p
}

func openForLock(t *testing.T, s *smb2.Share, p string) *smb2.File {
	t.Helper()
	f, err := s.OpenFile(p, os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTryLock_ExcludesAnotherClientUntilUnlocked(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	p := lockTestFile(t, "exclude")
	c2, s2 := secondShare(t)
	defer func() { _ = c2.Logoff() }()

	a := openForLock(t, fs, p)
	defer a.Close()
	b := openForLock(t, s2, p)
	defer b.Close()

	if err := a.TryLock(lockOffset, lockLength); err != nil {
		t.Fatal("first lock:", err)
	}
	for i := 0; i < 2; i++ { // the second attempt is the one servers answer with FILE_LOCK_CONFLICT
		if err := b.TryLock(lockOffset, lockLength); !errors.Is(err, smb2.ErrLockNotGranted) {
			t.Fatalf("attempt %d: want ErrLockNotGranted while another client holds the range, got %v", i+1, err)
		}
	}
	if err := a.Unlock(lockOffset, lockLength); err != nil {
		t.Fatal("unlock:", err)
	}
	if err := b.TryLock(lockOffset, lockLength); err != nil {
		t.Fatal("lock after the holder unlocked:", err)
	}
	if err := b.Unlock(lockOffset, lockLength); err != nil {
		t.Fatal(err)
	}
}

func TestTryLock_ReleasedWhenTheHolderClosesTheFile(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	p := lockTestFile(t, "close")
	c2, s2 := secondShare(t)
	defer func() { _ = c2.Logoff() }()

	a := openForLock(t, fs, p)
	if err := a.TryLock(lockOffset, lockLength); err != nil {
		t.Fatal(err)
	}
	_ = a.Close() // never unlocked

	b := openForLock(t, s2, p)
	defer b.Close()
	if err := b.TryLock(lockOffset, lockLength); err != nil {
		t.Fatal("a closed handle's lock must be released by the server:", err)
	}
}

func TestTryLock_ReleasedWhenTheHoldersSessionEnds(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	p := lockTestFile(t, "session")
	c2, s2 := secondShare(t)

	a := openForLock(t, s2, p)
	if err := a.TryLock(lockOffset, lockLength); err != nil {
		t.Fatal(err)
	}
	_ = c2.Logoff() // the holder's session goes away with the handle still open

	b := openForLock(t, fs, p)
	defer b.Close()
	if err := b.TryLock(lockOffset, lockLength); err != nil {
		t.Fatal("a lock whose session ended must be released by the server:", err)
	}
	_ = b.Unlock(lockOffset, lockLength)
}

func TestTryLock_DoesNotBlockWritesOutsideTheRange(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	p := lockTestFile(t, "writes")
	c2, s2 := secondShare(t)
	defer func() { _ = c2.Logoff() }()

	a := openForLock(t, fs, p)
	defer a.Close()
	if err := a.TryLock(lockOffset, lockLength); err != nil {
		t.Fatal(err)
	}
	b := openForLock(t, s2, p)
	defer b.Close()
	if _, err := b.WriteAt([]byte("data"), 0); err != nil {
		t.Fatal("a write far below the locked range must go through:", err)
	}
	_ = a.Unlock(lockOffset, lockLength)
}

func TestTryLock_RejectsAnEmptyOrNegativeRange(t *testing.T) {
	if fs == nil {
		t.Skip()
	}
	f := openForLock(t, fs, lockTestFile(t, "invalid"))
	defer f.Close()
	for _, r := range [][2]int64{{0, 0}, {-1, 1}, {0, -1}} {
		if err := f.TryLock(r[0], r[1]); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("TryLock(%d, %d): want os.ErrInvalid, got %v", r[0], r[1], err)
		}
	}
}
