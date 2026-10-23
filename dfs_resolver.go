package smb2

import (
	"context"
	"errors"
	"fmt"
	"github.com/maestrohub-labs/go-smb2/internal/utf16le"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/maestrohub-labs/go-smb2/internal/dfsc"
	"github.com/maestrohub-labs/go-smb2/internal/erref"
	"github.com/maestrohub-labs/go-smb2/internal/smb2"
)

const (
	// maxDFSHops bounds referral chaining (root -> link -> interlink ...)
	// so a misconfigured namespace cannot loop forever. cifs.ko uses the
	// same order of magnitude.
	maxDFSHops = 16
	// minRootTTL floors the cache lifetime of root/interlink entries.
	// Link entries use the server-supplied TimeToLive; roots change
	// rarely, so a short or zero server TTL is floored to avoid hammering
	// the namespace server.
	minRootTTL = 600 * time.Second
)

// dfsResolver follows DFS referrals to a backing (server, share, relPath)
// for one mounted share. It is created lazily on the first DFS-triggering
// error for a session.
type dfsResolver struct {
	cache  *referralCache
	conns  *backingConns
	origin *Session // the session the share is mounted on
	logf   func(format string, args ...any)
	// fetch retrieves one referral for unc from the named server. It is a
	// field so tests can drive the hop loop without a network; the live
	// constructor wires it to the IPC$ IOCTL on the server's session.
	fetch func(ctx context.Context, server, unc string) (*dfsc.ReferralResponse, error)

	mu           sync.Mutex
	leases       dfsLeases         // backing sessions used, see backingConns
	originShares map[string]*Share // shares mounted on origin, key: strings.ToLower(share)
}

func newDFSResolver(origin *Session) *dfsResolver {
	logf := origin.dialer.DFSLog
	if logf == nil {
		logf = func(string, ...any) {}
	}
	cache, conns := newReferralCache(), newBackingConns()
	if c := origin.dialer.DFSCache; c != nil {
		cache, conns = c.c, c.conns
	}
	r := &dfsResolver{
		cache:        cache,
		conns:        conns,
		origin:       origin,
		logf:         logf,
		leases:       make(dfsLeases),
		originShares: make(map[string]*Share),
	}
	r.fetch = func(ctx context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		sess, err := r.session(ctx, server)
		if err != nil {
			return nil, err
		}
		return sess.dfsGetReferral(ctx, unc)
	}
	return r
}

// session returns a session to server: the origin session if server is
// its server, else the backing session to it.
func (r *dfsResolver) session(ctx context.Context, server string) (*Session, error) {
	if strings.EqualFold(server, r.origin.serverName()) {
		return r.origin, nil
	}
	bc, err := r.conns.session(ctx, server, r.origin.dialer, r.leases)
	if err != nil {
		return nil, err
	}
	return bc.s, nil
}

// share returns a tree connect to \\server\share, see backingConn.share.
// Shares on the origin server are mounted on the origin session and are
// this resolver's own.
func (r *dfsResolver) share(ctx context.Context, server, share string, mapping utf16le.MapChars) (*Share, error) {
	if !strings.EqualFold(server, r.origin.serverName()) {
		bc, err := r.conns.session(ctx, server, r.origin.dialer, r.leases)
		if err != nil {
			return nil, err
		}
		return bc.share(server, share, mapping)
	}

	key := strings.ToLower(share)
	r.mu.Lock()
	defer r.mu.Unlock()
	if fs, ok := r.originShares[key]; ok && !fs.Closed() {
		return fs, nil
	}
	fs, err := r.origin.mountRaw(fmt.Sprintf(`\\%s\%s`, server, share), mapping)
	if err != nil {
		return nil, fmt.Errorf("dfs: mount backing \\\\%s\\%s: %w", server, share, err)
	}
	r.originShares[key] = fs
	return fs, nil
}

// close unmounts the shares on the origin session and gives up the
// backing sessions; the origin session itself is the caller's.
func (r *dfsResolver) close() {
	r.mu.Lock()
	for key, fs := range r.originShares {
		_ = fs.Umount()
		delete(r.originShares, key)
	}
	r.mu.Unlock()
	r.conns.release(r.leases)
}

// resolve follows DFS referrals for unc and returns the backing
// (server, share, relPath) of the first target. relPath uses backslash
// separators and has no leading separator. A non-DFS path (or one no
// longer covered) resolves to its own split, so resolve is safe to call
// speculatively.
func (r *dfsResolver) resolve(ctx context.Context, unc string) (server, share, relPath string, err error) {
	err = r.resolveWith(ctx, unc, func(s, sh, rel string) error {
		server, share, relPath = s, sh, rel
		return nil
	})
	return server, share, relPath, err
}

// resolveWith follows DFS referrals for unc and calls use with the
// resolved (server, share, relPath) until it succeeds. When a referral
// lists several targets they are tried in turn, the previously chosen
// one first (see referralCache), and the one that works is chosen for
// later calls. This applies at every hop, so both unreachable namespace
// servers and unreachable link targets (replicas) fail over.
func (r *dfsResolver) resolveWith(ctx context.Context, unc string, use func(server, share, relPath string) error) error {
	return r.resolveHop(ctx, normUNC(unc), use, map[string]bool{}, false)
}

// resolveHop resolves one referral hop for unc. visited holds the UNCs on
// the current chain, for loop detection. skipCache forces a fetch.
func (r *dfsResolver) resolveHop(ctx context.Context, unc string, use func(server, share, relPath string) error, visited map[string]bool, skipCache bool) error {
	if len(visited) >= maxDFSHops {
		return fmt.Errorf("dfs: exceeded %d referral hops resolving %q", maxDFSHops, unc)
	}
	key := strings.ToLower(unc)
	if visited[key] {
		return fmt.Errorf("dfs: referral loop resolving %q", unc)
	}
	visited[key] = true
	defer delete(visited, key)

	useUNC := func(u string) error {
		s, sh, rel := splitUNC(u)
		return use(s, sh, rel)
	}

	entry, cached := r.cache.longestPrefix(unc)
	if !cached || skipCache {
		srv := serverFromUNC(unc)
		if srv == "" {
			return fmt.Errorf("dfs: cannot extract server from %q", unc)
		}
		resp, err := r.fetch(ctx, srv, unc)
		if err != nil {
			if isNotDFSReferral(err) {
				// The path is not (or no longer) DFS-covered: use it
				// as-is. This terminates chains whose final hop lands on
				// a plain file server.
				return useUNC(unc)
			}
			return fmt.Errorf("dfs: referral for %q: %w", unc, err)
		}
		var ok bool
		if entry, ok = r.cacheResponse(unc, resp); !ok {
			// No usable target — treat as not covered.
			return useUNC(unc)
		}
		cached = false
	}

	suffix := unc[len(entry.consumedPrefix):]
	// try resolves unc through the target t.
	try := func(t string) error {
		next := t + suffix
		// Terminal when: a storage link target, or a root referral with
		// nothing left to resolve below it (we simply connect to the root
		// target). Otherwise the next hop asks the root/interlink target to
		// resolve the remaining suffix, which is how a namespace-front-end
		// (Case A) path that then crosses a link gets fully followed.
		if entry.final || suffix == "" {
			return useUNC(next)
		}
		if strings.EqualFold(next, unc) {
			// A self-referential (standalone) root: the root target IS
			// the namespace just consumed. Fresh from the server, that
			// means no link covers the path, so it is a plain path under
			// the root. A cached root says nothing about links below it,
			// so ask the root target about this path.
			if !cached {
				return useUNC(next)
			}
			delete(visited, key)
			return r.resolveHop(ctx, unc, use, visited, true)
		}
		return r.resolveHop(ctx, next, use, visited, false)
	}

	targets, pinned := r.cache.ordered(entry)
	var errs []error
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := try(t)
		if err != nil {
			r.logf("smb2 dfs: target %s for %s failed: %v", t, entry.consumedPrefix, err)
			errs = append(errs, err)
			continue
		}
		if chosen := r.cache.pin(entry.consumedPrefix, t, pinned); !strings.EqualFold(chosen, t) {
			// Another caller chose a different target meanwhile. Use
			// theirs if possible, so all callers see the same replica.
			if try(chosen) == nil {
				return nil
			}
		}
		return nil
	}
	return errors.Join(errs...)
}

// cacheResponse caches the referral resp received for unc and returns the
// entry. ok is false if resp has no usable target.
func (r *dfsResolver) cacheResponse(unc string, resp *dfsc.ReferralResponse) (entry referralEntry, ok bool) {
	var targets []string
	var first *dfsc.Referral
	for i := range resp.Referrals {
		if resp.Referrals[i].TargetUNC == "" {
			continue
		}
		if first == nil {
			first = &resp.Referrals[i]
		}
		targets = append(targets, resp.Referrals[i].TargetUNC)
	}
	if first == nil || resp.PathConsumed == 0 {
		return referralEntry{}, false
	}

	// Classify the response. [MS-DFSC] sets the StorageServers header
	// flag for BOTH link referrals (the target IS storage) AND root
	// referrals (ServerType=ROOT — the target is a root/namespace
	// server you connect to in order to keep resolving). So storage
	// alone does NOT mean "stop": a root referral is terminal only
	// when no path remains below the root.
	consumed := utf16Prefix(unc, resp.PathConsumed)
	storage := resp.HeaderFlags&dfsc.HeaderFlagStorageServers != 0

	// A terminal link mapping (storage link, not an interlink) can be
	// cached and reused for any path under consumed. A root mapping is
	// cached too (to skip re-querying the namespace front end) but is
	// never blindly terminal — terminality is recomputed from the
	// remaining suffix on every hit.
	terminalLink := !first.IsRootTarget() && storage
	ttl := first.TTL
	if !terminalLink && ttl < minRootTTL {
		ttl = minRootTTL
	}
	if ttl <= 0 {
		ttl = minRootTTL
	}
	r.cache.put(consumed, targets, ttl, terminalLink)
	return referralEntry{consumedPrefix: consumed, targets: targets, final: terminalLink}, true
}

// cachedLink reports whether the cache alone shows that unc is behind a
// DFS link, so an open can go straight to the target instead of first
// being refused with STATUS_PATH_NOT_COVERED.
func (r *dfsResolver) cachedLink(unc string) bool {
	unc = normUNC(unc)
	for range maxDFSHops {
		entry, ok := r.cache.longestPrefix(unc)
		if !ok {
			return false
		}
		if entry.final {
			return true
		}
		suffix := unc[len(entry.consumedPrefix):]
		targets, _ := r.cache.ordered(entry)
		next := targets[0] + suffix
		if suffix == "" || strings.EqualFold(next, unc) {
			return false
		}
		unc = next
	}
	return false
}

// isNotDFSReferral reports whether err means "this path is not served by
// DFS" — the benign signal that resolution has reached a plain file
// server (or that the path was never DFS). It is treated as "use the path
// as-is", not a failure.
func isNotDFSReferral(err error) bool {
	var re *ResponseError
	if !errors.As(err, &re) {
		return false
	}
	switch erref.NtStatus(re.Code) {
	case erref.STATUS_NOT_FOUND,
		erref.STATUS_OBJECT_NAME_NOT_FOUND,
		erref.STATUS_OBJECT_PATH_NOT_FOUND,
		erref.STATUS_NOT_SUPPORTED,
		erref.STATUS_INVALID_DEVICE_REQUEST,
		erref.STATUS_NO_SUCH_DEVICE,
		erref.STATUS_FS_DRIVER_REQUIRED:
		return true
	}
	return false
}

// supportsDFS reports whether the session's server advertised the DFS
// global capability during negotiation.
func (c *Session) supportsDFS() bool {
	return c.s.capabilities&smb2.SMB2_GLOBAL_CAP_DFS != 0
}

// --- UNC helpers --------------------------------------------------------

// normUNC normalizes any UNC form to a single-leading-backslash path
// (`\server\share\...`), the form MS-DFSC RequestFileName uses and that
// PathConsumed is measured against. Forward slashes become backslashes.
func normUNC(unc string) string {
	unc = strings.ReplaceAll(unc, "/", `\`)
	unc = strings.TrimLeft(unc, `\`)
	return `\` + unc
}

// serverFromUNC returns the server component of `\server\share\...`.
func serverFromUNC(unc string) string {
	parts := strings.Split(strings.TrimLeft(normUNC(unc), `\`), `\`)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// splitUNC splits `\server\share\rel\path` into its server, share, and
// share-relative remainder (backslash-separated, no leading separator).
func splitUNC(unc string) (server, share, relPath string) {
	parts := strings.Split(strings.TrimLeft(normUNC(unc), `\`), `\`)
	switch len(parts) {
	case 0:
		return "", "", ""
	case 1:
		return parts[0], "", ""
	case 2:
		return parts[0], parts[1], ""
	default:
		return parts[0], parts[1], strings.Join(parts[2:], `\`)
	}
}

// utf16Prefix returns the prefix of s covered by pathConsumedBytes bytes
// of UTF-16 (so /2 = code units). Counting in UTF-16 units matches how
// the server measured PathConsumed and avoids the classic byte-vs-char
// off-by-two bug on non-ASCII paths.
func utf16Prefix(s string, pathConsumedBytes uint16) string {
	units := utf16.Encode([]rune(s))
	n := min(int(pathConsumedBytes)/2, len(units))
	return string(utf16.Decode(units[:n]))
}

// utf16Suffix returns the remainder of s after pathConsumedBytes bytes of
// UTF-16, the part of the path not covered by the referral.
func utf16Suffix(s string, pathConsumedBytes uint16) string {
	units := utf16.Encode([]rune(s))
	n := min(int(pathConsumedBytes)/2, len(units))
	return string(utf16.Decode(units[n:]))
}
