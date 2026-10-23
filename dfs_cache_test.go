package smb2

import (
	"testing"
	"time"
)

func TestReferralCache_PutLongestPrefix(t *testing.T) {
	c := newReferralCache()
	c.put(`\ns\dfs`, []string{`\rootsrv\dfs`}, time.Hour, false)
	c.put(`\ns\dfs\link`, []string{`\backing\share`}, time.Hour, true)

	// A query under the link must match the longer, more specific entry.
	e, ok := c.longestPrefix(`\ns\dfs\link\sub\file.csv`)
	if !ok {
		t.Fatal("expected a cache hit")
	}
	if e.consumedPrefix != `\ns\dfs\link` {
		t.Errorf("matched %q, want the longest prefix %q", e.consumedPrefix, `\ns\dfs\link`)
	}
	if !e.final {
		t.Error("link entry should be final")
	}

	// A query that only reaches the root must match the shorter entry.
	e, ok = c.longestPrefix(`\ns\dfs\other`)
	if !ok || e.consumedPrefix != `\ns\dfs` {
		t.Fatalf("got (%v,%v), want root entry", e.consumedPrefix, ok)
	}
}

func TestReferralCache_CaseInsensitive(t *testing.T) {
	c := newReferralCache()
	c.put(`\NS\DFS\Link`, []string{`\backing\share`}, time.Hour, true)
	if _, ok := c.longestPrefix(`\ns\dfs\link\x`); !ok {
		t.Error("DFS lookup must be case-insensitive")
	}
}

func TestReferralCache_BoundaryOnly(t *testing.T) {
	c := newReferralCache()
	c.put(`\srv\share`, []string{`\b\sh`}, time.Hour, true)
	// `\srv\share2` must NOT match `\srv\share` (different component).
	if _, ok := c.longestPrefix(`\srv\share2\f`); ok {
		t.Error("prefix match must respect component boundaries")
	}
	// exact match is allowed
	if _, ok := c.longestPrefix(`\srv\share`); !ok {
		t.Error("exact match should hit")
	}
}

func TestReferralCache_Expiry(t *testing.T) {
	c := newReferralCache()
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }

	c.put(`\ns\link`, []string{`\b\s`}, 60*time.Second, true)
	if _, ok := c.longestPrefix(`\ns\link\f`); !ok {
		t.Fatal("entry should be live before expiry")
	}

	now = now.Add(61 * time.Second)
	if _, ok := c.longestPrefix(`\ns\link\f`); ok {
		t.Error("entry should be expired and evicted")
	}
	// confirm eviction actually removed it from the map
	if len(c.m) != 0 {
		t.Errorf("expired entry not evicted: %d remain", len(c.m))
	}
}

func TestBoundaryPrefix(t *testing.T) {
	cases := []struct {
		s, prefix string
		want      bool
	}{
		{`\a\b\c`, `\a\b`, true},
		{`\a\b`, `\a\b`, true},
		{`\a\bc`, `\a\b`, false},
		{`\a\b`, `\a\bc`, false},
		{`\a\b\c`, `\x`, false},
	}
	for _, tc := range cases {
		if got := boundaryPrefix(tc.s, tc.prefix); got != tc.want {
			t.Errorf("boundaryPrefix(%q,%q)=%v, want %v", tc.s, tc.prefix, got, tc.want)
		}
	}
}
