package smb2

import (
	"strings"
	"sync"
	"time"
)

// DFSCache holds DFS referrals and the targets chosen for them. By
// default every mounted share has its own. Setting the same DFSCache on
// the Dialers of several sessions makes them share referrals and agree on
// targets, so they all see the same replica of a replicated DFS link, as
// a single Windows client would. A DFSCache is safe for concurrent use.
//
// The sessions also share their connections to DFS targets: one session
// to each target server, used by all of them, rather than one each.
// These are logged off when the last session using them unmounts its
// share.
type DFSCache struct {
	c     *referralCache
	conns *backingConns
}

// NewDFSCache returns an empty DFSCache.
func NewDFSCache() *DFSCache {
	return &DFSCache{c: newReferralCache(), conns: newBackingConns()}
}

// referralEntry is one cached DFS mapping: a consumed namespace prefix
// that resolves to a target UNC prefix, valid until deadline.
type referralEntry struct {
	// consumedPrefix is the namespace-side prefix this entry replaces,
	// in original case (its byte length is used to strip it from a query
	// UNC). DFS names are effectively ASCII, so byte length and the
	// case-folded match length agree.
	consumedPrefix string
	// targets are the UNC prefixes that consumedPrefix maps to, e.g.
	// `\backing\share`, in the order the server listed them. Several
	// targets are replicas (link) or namespace servers (root).
	targets []string
	// deadline is when this entry expires (now + TTL at insertion).
	deadline time.Time
	// final reports whether target is a storage server (terminal). When
	// false the target is itself a DFS server whose path needs further
	// resolution (a root / interlink referral).
	final bool
}

// referralCache is a TTL cache of DFS referrals keyed by the lowercased
// consumed-prefix UNC (DFS is case-insensitive). Lookup is a
// longest-prefix match on a path-component boundary; expired entries are
// evicted lazily on access.
//
// It also records the target chosen for each referral. Choices outlive
// the entries, so a target stays in use after a referral is refreshed
// for as long as the server still lists it: like the Windows client, the
// same replica is used until it fails, rather than whichever the server
// happens to list first on each refresh.
type referralCache struct {
	mu sync.Mutex
	m  map[string]referralEntry // key: strings.ToLower(consumedPrefix)
	// pins maps strings.ToLower(consumedPrefix) to the chosen target.
	pins map[string]string
	// now is the clock, overridable in tests.
	now func() time.Time
}

func newReferralCache() *referralCache {
	return &referralCache{m: make(map[string]referralEntry), pins: make(map[string]string), now: time.Now}
}

// put inserts or replaces the mapping for consumedPrefix.
func (c *referralCache) put(consumedPrefix string, targets []string, ttl time.Duration, final bool) {
	if consumedPrefix == "" || len(targets) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[strings.ToLower(consumedPrefix)] = referralEntry{
		consumedPrefix: consumedPrefix,
		targets:        targets,
		deadline:       c.now().Add(ttl),
		final:          final,
	}
}

// ordered returns e's targets in the order they should be tried: the
// chosen one first if the server still lists it, then the others in
// server order. pinned is the choice as read, to pass back to pin.
func (c *referralCache) ordered(e referralEntry) (targets []string, pinned string) {
	c.mu.Lock()
	pinned = c.pins[strings.ToLower(e.consumedPrefix)]
	c.mu.Unlock()
	targets = make([]string, 0, len(e.targets))
	for _, t := range e.targets {
		if strings.EqualFold(t, pinned) {
			targets = append([]string{t}, targets...)
		} else {
			targets = append(targets, t)
		}
	}
	return targets, pinned
}

// pin records target as the choice for consumedPrefix if the choice is
// still prev, the value ordered returned. It returns the choice after
// the call: if another caller chose differently in the meantime, theirs
// is kept and returned so all callers converge on one target.
func (c *referralCache) pin(consumedPrefix, target, prev string) string {
	key := strings.ToLower(consumedPrefix)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur := c.pins[key]; cur != prev && cur != "" {
		return cur
	}
	c.pins[key] = target
	return target
}

// longestPrefix returns the cached entry whose lowercased consumedPrefix
// is the longest path-component-boundary prefix of unc and has not
// expired. Expired entries encountered during the scan are evicted.
func (c *referralCache) longestPrefix(unc string) (referralEntry, bool) {
	lower := strings.ToLower(unc)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	var best referralEntry
	var bestLen = -1
	for key, entry := range c.m {
		if !entry.deadline.After(now) {
			delete(c.m, key) // evict expired
			continue
		}
		if !boundaryPrefix(lower, key) {
			continue
		}
		if len(key) > bestLen {
			best, bestLen = entry, len(key)
		}
	}
	if bestLen < 0 {
		return referralEntry{}, false
	}
	return best, true
}

// boundaryPrefix reports whether prefix is a prefix of s that ends on a
// path-component boundary — i.e. s equals prefix, or the character of s
// right after prefix is a path separator. This stops `\srv\share` from
// matching a query for `\srv\share2`.
func boundaryPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	return len(s) == len(prefix) || s[len(prefix)] == '\\'
}
