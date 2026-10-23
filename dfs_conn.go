package smb2

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/maestrohub-labs/go-smb2/internal/utf16le"
)

// dfsPort is the port DFS referrals are always resolved on. Referrals are
// name-based and assume the standard SMB port; a referral never carries a
// port, so backing servers are always dialed on 445.
const dfsPort = "445"

// backingConns owns the SMB sessions to DFS backing servers named in
// referrals, one per server, and the shares mounted on them. The
// resolvers of a DFSCache share one, so all sessions using the cache have
// a single session to each backing server, as a Windows client does,
// rather than one each. Resolvers lease the sessions they use, and a
// session is logged off when its last lease is released.
type backingConns struct {
	mu    sync.Mutex
	conns map[string]*backingConn // key: strings.ToLower(server)
}

func newBackingConns() *backingConns {
	return &backingConns{conns: make(map[string]*backingConn)}
}

// backingConn is the session to one backing server.
type backingConn struct {
	key    string
	dialed chan struct{} // closed when the dial has finished
	s      *Session      // the session, once dialed without error
	err    error         // the dial error
	refs   int           // leases, guarded by backingConns.mu

	sharesMu sync.Mutex
	shares   map[string]*Share // key: strings.ToLower(share)
}

// dfsLeases records the backing sessions one resolver uses. It is
// guarded by backingConns.mu.
type dfsLeases map[*backingConn]bool

// unusable reports whether bc's dial failed or its connection has died.
// It is false while the dial is in progress.
func (bc *backingConn) unusable() bool {
	select {
	case <-bc.dialed:
		return bc.err != nil || bc.s.Closed()
	default:
		return false
	}
}

// session returns the session to server, dialing it with d's settings if
// there is none or it has died, and leases it in leases. Concurrent
// callers wait for a single dial.
func (b *backingConns) session(ctx context.Context, server string, d Dialer, leases dfsLeases) (*backingConn, error) {
	key := strings.ToLower(server)

	b.mu.Lock()
	bc := b.conns[key]
	if bc != nil && bc.unusable() {
		delete(b.conns, key) // dial again
		bc = nil
	}
	dial := bc == nil
	if dial {
		bc = &backingConn{key: key, dialed: make(chan struct{}), shares: make(map[string]*Share)}
		b.conns[key] = bc
	}
	if !leases[bc] {
		leases[bc] = true
		bc.refs++
	}
	b.mu.Unlock()

	if dial {
		d.Initiator = initiatorFor(d.Initiator, server)
		bc.s, bc.err = d.Dial(ctx, net.JoinHostPort(server, dfsPort))
		if bc.err != nil {
			bc.err = fmt.Errorf("dfs: dial backing server %s: %w", server, bc.err)
		}
		close(bc.dialed)
	} else {
		select {
		case <-bc.dialed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if bc.err != nil {
		return nil, bc.err
	}
	return bc, nil
}

// share returns a tree connect to \\server\share on bc, mounting it on
// first use or if its connection has died. The returned share has no
// DFS router of its own: it is reached only via createFile retries
// whose paths are already fully resolved, so it needs no further routing.
func (bc *backingConn) share(server, share string, mapping utf16le.MapChars) (*Share, error) {
	key := strings.ToLower(share)

	bc.sharesMu.Lock()
	defer bc.sharesMu.Unlock()

	if fs, ok := bc.shares[key]; ok && !fs.Closed() {
		return fs, nil
	}
	fs, err := bc.s.mountRaw(fmt.Sprintf(`\\%s\%s`, server, share), mapping)
	if err != nil {
		return nil, fmt.Errorf("dfs: mount backing \\\\%s\\%s: %w", server, share, err)
	}
	bc.shares[key] = fs
	return fs, nil
}

// release gives up leases. Sessions nobody leases any more are logged
// off, after unmounting their shares.
func (b *backingConns) release(leases dfsLeases) {
	var unused []*backingConn
	b.mu.Lock()
	for bc := range leases {
		bc.refs--
		if bc.refs == 0 {
			if b.conns[bc.key] == bc {
				delete(b.conns, bc.key)
			}
			unused = append(unused, bc)
		}
	}
	clear(leases)
	b.mu.Unlock()

	for _, bc := range unused {
		bc.close()
	}
}

// close unmounts bc's shares and logs off its session.
func (bc *backingConn) close() {
	<-bc.dialed
	if bc.s == nil {
		return
	}
	bc.sharesMu.Lock()
	for key, fs := range bc.shares {
		_ = fs.Umount()
		delete(bc.shares, key)
	}
	bc.sharesMu.Unlock()
	_ = bc.s.Logoff()
}

// initiatorFor returns an initiator that authenticates to the backing
// server with the credentials of i. Each session needs an initiator of
// its own, as it holds the state of the session's authentication, and
// the server's SPN is its own: a Kerberos ticket for the server the
// credentials were set up for is not valid for another one.
func initiatorFor(i Initiator, server string) Initiator {
	switch i := i.(type) {
	case *NTLMInitiator:
		c := &NTLMInitiator{
			User:        i.User,
			Password:    i.Password,
			Hash:        i.Hash,
			Domain:      i.Domain,
			Workstation: i.Workstation,
		}
		if i.TargetSPN != "" {
			c.TargetSPN = "cifs/" + server
		}
		return c
	case *Krb5Initiator:
		return &Krb5Initiator{Client: i.Client, TargetSPN: "cifs/" + server}
	}
	return i
}
