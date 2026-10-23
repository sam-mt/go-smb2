package smb2

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/maestrohub-labs/go-smb2/internal/erref"
	"github.com/maestrohub-labs/go-smb2/internal/smb2"
	"github.com/maestrohub-labs/go-smb2/internal/utf16le"
)

// dfsRouter carries transparent-DFS state for a top-level Share. It maps
// share-relative operation names to (a) the path actually sent to the
// underlying tree connect and (b) the namespace UNC used to re-resolve a
// referral when the server reports the path crossed a DFS link.
type dfsRouter struct {
	resolver *dfsResolver
	// namespacePrefix is the UNC this share represents (e.g. `\server\share`
	// for a plain mount, or the originally-requested `\nsroot\dfs` for a
	// Case-A namespace-root mount). Operation names append to it to form
	// the full UNC for referral resolution.
	namespacePrefix string
	// pathPrefix is prepended to operation names before they are sent to
	// the underlying tree connect. Non-empty only for a Case-A mount whose
	// backing target sits below the backing share root.
	pathPrefix string
	// borrowedTree is set for a Case-A mount, whose treeConn is the
	// resolver's cached backing tree. The resolver disconnects it in
	// close, so Umount must not disconnect it a second time (on a session
	// that close has already logged off, which blocks forever).
	borrowedTree bool
}

// opPath joins the share-relative op name with the Case-A path prefix to
// get the path to send to the backing tree connect.
func (d *dfsRouter) opPath(name string) string {
	name = strings.TrimLeft(name, `\/`)
	if name == "." {
		// A caller-supplied "." means the share root. Normalise it to the
		// empty name up front so both branches below treat root uniformly.
		name = ""
	}
	if d.pathPrefix == "" {
		// Root (or any op) on a plain-mounted share. The root MUST be the
		// empty string, never ".": opPath feeds createFileRaw, which
		// bypasses normPath, so a literal "." is sent verbatim and Windows
		// rejects it with STATUS_OBJECT_NAME_INVALID (Samba tolerates it).
		// This matches createFile, which passes "" for the target share
		// root after following a referral.
		return name
	}
	if name == "" {
		return d.pathPrefix
	}
	return d.pathPrefix + `\` + name
}

// fullUNC builds the namespace-side UNC for an op name, for referral
// resolution.
func (d *dfsRouter) fullUNC(name string) string {
	name = strings.TrimLeft(name, `\/`)
	if name == "" || name == "." {
		return d.namespacePrefix
	}
	return d.namespacePrefix + `\` + name
}

// attachDFS wires a freshly tree-connected Share with DFS routing.
func attachDFS(fs *Share, r *dfsResolver, namespaceUNC, pathPrefix string, ownsResolver bool) {
	fs.dfs = &dfsRouter{
		resolver:        r,
		namespacePrefix: normUNC(namespaceUNC),
		pathPrefix:      pathPrefix,
	}
	fs.ownsResolver = ownsResolver
}

// dfsMount handles Case A: the requested share is a DFS namespace root (or
// otherwise not covered by this server), so treeConnect failed. It
// resolves the referral and mounts the backing target, returning a share
// whose operations are transparently prefixed with the backing-relative
// path. On any resolution failure it returns the original mount error so
// the caller sees the real cause rather than a DFS artifact.
func (c *Session) dfsMount(sharename string, mapping utf16le.MapChars, origErr error) (*Share, error) {
	r := newDFSResolver(c)
	c.warnIfNoDFSCap(r)

	backing, rel, err := r.target(c.ctx, sharename, mapping)
	if err != nil {
		r.close()
		return nil, fmt.Errorf("%w: following DFS referral: %w", origErr, err)
	}

	// Return a distinct share view that owns the resolver and prepends the
	// backing-relative prefix; the cached backing share itself stays
	// prefix-free for reuse by mid-op retries.
	fs := &Share{treeConn: backing.treeConn, ctx: context.Background(), mapping: mapping}
	attachDFS(fs, r, sharename, rel, true)
	fs.dfs.borrowedTree = true
	return fs, nil
}

// createFile is the DFS-aware wrapper over createFileRaw. For a non-DFS
// share it is a straight passthrough. For a DFS share it applies any
// Case-A path prefix and, if the server reports the path crossed a DFS
// link, resolves the referral and retries the CREATE against the target.
//
// Resolution is driven by the server's STATUS_PATH_NOT_COVERED, as in
// Samba's client, rather than by querying referrals up front: with DFS
// path names (see createFileDFS) a DFS root reports every path behind a
// link this way.
func (fs *Share) createFile(name string, req *smb2.CreateRequest, followSymlinks bool) (*File, error) {
	if fs.dfs == nil {
		return fs.createFileRaw(name, req, followSymlinks)
	}

	// A path the cache already knows to be behind a link goes straight to
	// the link's target, saving a round trip to be refused.
	var err error
	if !fs.dfs.resolver.cachedLink(fs.dfs.fullUNC(name)) {
		var f *File
		f, err = fs.createFileDFS(fs.dfs.opPath(name), req, followSymlinks)
		if err == nil || !isPathNotCovered(err) {
			return f, err
		}
	}

	// The path crosses a DFS link. Follow the whole referral chain to a
	// terminal storage target. If that fails return why, never the link's
	// local stub: that would be the wrong data.
	backing, rel, rerr := fs.dfs.resolver.target(fs.ctx, fs.dfs.fullUNC(name), fs.mapping)
	if rerr != nil {
		if err == nil {
			return nil, rerr
		}
		return nil, fmt.Errorf("%w: following DFS referral: %w", err, rerr)
	}
	// The open on the target is the real result, errors included. rel is
	// "" for the target share root: createFileRaw bypasses normPath, so
	// the root MUST be the empty name, as a literal "." is rejected by
	// Windows with STATUS_OBJECT_NAME_INVALID.
	f, err := backing.WithContext(fs.ctx).createFileDFS(rel, req, followSymlinks)
	if err != nil && backing.Closed() {
		// The cached connection to the target had died. Retry once on a
		// new one, or on another target if this one is now unreachable.
		fs.dfs.resolver.logf("smb2 dfs: connection to target of %s closed, reconnecting: %v", fs.dfs.fullUNC(name), err)
		backing, rel, rerr = fs.dfs.resolver.target(fs.ctx, fs.dfs.fullUNC(name), fs.mapping)
		if rerr != nil {
			return nil, fmt.Errorf("%w: reconnecting to DFS target: %w", err, rerr)
		}
		f, err = backing.WithContext(fs.ctx).createFileDFS(rel, req, followSymlinks)
	}
	return f, err
}

// createFileDFS opens the share-relative name on fs, which may be a DFS
// root. On a DFS share (SMB2_SHAREFLAG_DFS) the request is flagged as a
// DFS operation and the name is sent as the DFS path `server\share\name`.
// With the flag set the server strips the first two components of the
// name before opening it ([MS-SMB2] 2.2.13, 3.3.5.9), so a share-relative
// name is misread: `a\b\c` would open `c` at the share root. The flag is
// also what makes the server report STATUS_PATH_NOT_COVERED for paths
// behind a link. On other shares the flag must not be set.
func (fs *Share) createFileDFS(name string, req *smb2.CreateRequest, followSymlinks bool) (*File, error) {
	if fs.shareFlags&smb2.SMB2_SHAREFLAG_DFS == 0 {
		req.Header().Flags &^= smb2.SMB2_FLAGS_DFS_OPERATIONS
		return fs.createFileRaw(name, req, followSymlinks)
	}
	req.Header().Flags |= smb2.SMB2_FLAGS_DFS_OPERATIONS
	f, err := fs.createFileRaw(dfsPathName(fs.path, name), req, followSymlinks)
	if err != nil {
		return nil, err
	}
	f.name = name
	f.fileStat.FileName = base(name)
	return f, nil
}

// dfsPathName returns the DFS path name `server\share\name` for the
// share-relative name on the tree connected as treePath (`\\server\share`).
// The share root is `server\share`.
func dfsPathName(treePath, name string) string {
	dfsName := strings.TrimLeft(treePath, `\`)
	if name != "" {
		dfsName += `\` + name
	}
	return dfsName
}

// target follows the referrals for unc and returns the target share,
// connected, and the path of unc on it. Targets that can't be connected
// to are skipped in favour of the next one the referral lists.
func (r *dfsResolver) target(ctx context.Context, unc string, mapping utf16le.MapChars) (backing *Share, relPath string, err error) {
	err = r.resolveWith(ctx, unc, func(server, share, rel string) error {
		if share == "" {
			return fmt.Errorf("dfs: no target share for %q", unc)
		}
		b, err := r.share(ctx, server, share, mapping)
		if err != nil {
			return err
		}
		backing, relPath = b, rel
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return backing, relPath, nil
}

// ErrDFSCrossTarget is returned (wrapped) by Share.Rename when the old and
// new paths are on different DFS targets, e.g. one behind a link and one
// not, so the server can't rename one to the other. Copy and delete
// instead.
var ErrDFSCrossTarget = errors.New("dfs: rename across DFS targets")

// dfsRenameTarget returns the rename destination to send for newpath, f
// being oldpath opened for the rename. The destination is a path on the
// share f was opened on, which for a path behind a DFS link is the link's
// target, not fs. It returns ErrDFSCrossTarget if newpath is on another
// target than oldpath.
func (fs *Share) dfsRenameTarget(f *File, oldpath, newpath string) (string, error) {
	local := f.fs.treeConn == fs.treeConn
	if local && fs.shareFlags&smb2.SMB2_SHAREFLAG_DFS == 0 {
		// Only a DFS root has links, so newpath is on this share too.
		return fs.dfs.opPath(newpath), nil
	}
	oldServer, oldShare, _, err := fs.dfs.resolver.resolve(fs.ctx, fs.dfs.fullUNC(oldpath))
	if err != nil {
		return "", err
	}
	newServer, newShare, newRel, err := fs.dfs.resolver.resolve(fs.ctx, fs.dfs.fullUNC(newpath))
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(oldServer, newServer) || !strings.EqualFold(oldShare, newShare) {
		return "", ErrDFSCrossTarget
	}
	if local {
		return fs.dfs.opPath(newpath), nil
	}
	return newRel, nil
}

// mountRaw tree-connects to sharename and returns a plain Share with no
// DFS routing. Used for DFS backing targets, whose paths are already
// fully resolved.
func (c *Session) mountRaw(sharename string, mapping utf16le.MapChars) (*Share, error) {
	tc, err := treeConnect(c.ctx, c.s, sharename, 0, mapping)
	if err != nil {
		return nil, err
	}
	return &Share{treeConn: tc, ctx: context.Background(), mapping: mapping}, nil
}

// warnIfNoDFSCap emits a one-line diagnostic (rule 30) when DFS following
// was requested but the server advertised no DFS capability, so callers
// are not left wondering why referrals are never followed.
func (c *Session) warnIfNoDFSCap(r *dfsResolver) {
	if !c.supportsDFS() {
		r.logf("smb2 dfs: EnableDFS set but server %s advertised no DFS capability; referral following is inert", c.serverName())
	}
}

// isIPCShare reports whether sharename targets the inter-process
// communication share. DFS routing must never attach to \IPC$ (the DFS
// referral IOCTL itself mounts \IPC$, which would otherwise recurse).
func isIPCShare(sharename string) bool {
	return strings.HasSuffix(strings.ToUpper(strings.TrimRight(sharename, `\`)), `\IPC$`)
}

// isPathNotCovered reports whether err is STATUS_PATH_NOT_COVERED — the
// mid-operation signal that a path crossed a DFS link.
func isPathNotCovered(err error) bool {
	var re *ResponseError
	return errors.As(err, &re) && erref.NtStatus(re.Code) == erref.STATUS_PATH_NOT_COVERED
}

// isDFSResolvable reports whether a failed tree connect (Case A) is a
// DFS-shaped error worth attempting referral resolution for.
func isDFSResolvable(err error) bool {
	var re *ResponseError
	if !errors.As(err, &re) {
		return false
	}
	switch erref.NtStatus(re.Code) {
	case erref.STATUS_BAD_NETWORK_NAME,
		erref.STATUS_PATH_NOT_COVERED,
		erref.STATUS_DFS_UNAVAILABLE:
		return true
	}
	return false
}
