// Command dfsprobe is a standalone smoke test for transparent DFS referral
// following. It mirrors the maestrohub connector's exact SMB dialing path
// (NTLM auth, RequireMessageSigning optional, EnableDFS=true with a DFSLog
// sink) and then exercises the two failure modes from issue #2431:
//
//	Case A — the -share is a DFS namespace root: Mount must resolve the
//	         root referral and connect to a backing root target instead of
//	         failing with STATUS_BAD_NETWORK_NAME.
//	Case B — the -path crosses a DFS link inside the share: Stat/Open must
//	         follow the link referral instead of failing with
//	         STATUS_PATH_NOT_COVERED.
//
// It is intentionally dependency-free beyond the fork itself, so it can be
// run straight from a checkout on the connector host:
//
//	go run ./cmd/dfsprobe \
//	    -host 10.176.0.40 -share Data -path "CKY/Departments" \
//	    -user alice -pass secret -domain CORP
//
// Exit code 0 means the file/dir at -path was reached and read; non-zero
// means it failed (the error is printed). Nothing is written to the share.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	smb2 "github.com/sam-mt/go-smb2"
)

func main() {
	var (
		host    = flag.String("host", "", "SMB server / DFS namespace host or IP (required)")
		port    = flag.Int("port", 445, "SMB port")
		share   = flag.String("share", "", "share name, e.g. Data (required); may be a DFS namespace root")
		relPath = flag.String("path", "", "share-relative path to read; may cross DFS links. Empty = just the share root")
		user    = flag.String("user", "", "username (empty = anonymous/guest)")
		pass    = flag.String("pass", "", "password")
		domain  = flag.String("domain", "", "NTLM domain / workgroup")
		sign    = flag.Bool("sign", false, "require SMB message signing (match connector RequireSigning)")
		nRead   = flag.Int("read", 512, "bytes to read from the target file (0 = skip read)")
		timeout = flag.Duration("timeout", 20*time.Second, "overall dial/negotiate timeout")
	)
	flag.Parse()

	if *host == "" || *share == "" {
		fmt.Fprintln(os.Stderr, "error: -host and -share are required")
		flag.Usage()
		os.Exit(2)
	}

	if err := run(probeConfig{
		host: *host, port: *port, share: *share, relPath: *relPath,
		user: *user, pass: *pass, domain: *domain, sign: *sign,
		nRead: *nRead, timeout: *timeout,
	}); err != nil {
		fmt.Printf("\nFAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\nPASS: share mounted and target reached through DFS.")
}

type probeConfig struct {
	host, share, relPath string
	port                 int
	user, pass, domain   string
	sign                 bool
	nRead                int
	timeout              time.Duration
}

func run(cfg probeConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	endpoint := net.JoinHostPort(cfg.host, fmt.Sprint(cfg.port))
	step("dialing TCP %s", endpoint)
	tcpConn, err := (&net.Dialer{Timeout: cfg.timeout}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return fmt.Errorf("TCP dial %s: %w", endpoint, err)
	}
	defer tcpConn.Close()

	// Mirror the connector's Dialer exactly: DFS always on, with a DFSLog
	// sink so we can see referral diagnostics (and the "no DFS capability"
	// warning, which would explain silent non-following).
	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: cfg.sign},
		EnableDFS:  true,
		DFSLog: func(format string, args ...any) {
			fmt.Printf("    [dfs] "+format+"\n", args...)
		},
	}
	if cfg.user == "" {
		d.Initiator = &smb2.NTLMInitiator{} // anonymous / guest
	} else {
		d.Initiator = &smb2.NTLMInitiator{User: cfg.user, Password: cfg.pass, Domain: cfg.domain}
	}

	step("negotiate + NTLM session setup (user=%q domain=%q signing=%v)", cfg.user, cfg.domain, cfg.sign)
	session, err := d.DialConn(ctx, tcpConn, endpoint)
	if err != nil {
		return fmt.Errorf("SMB session setup: %w", err)
	}
	defer session.Logoff()
	session = session.WithContext(ctx)

	// Case A: mounting a DFS namespace root. With the fix this resolves the
	// root referral and connects to a backing root target; without DFS it
	// would fail STATUS_BAD_NETWORK_NAME.
	mountPath := fmt.Sprintf(`\\%s\%s`, cfg.host, cfg.share)
	step("Mount %s  (Case A: namespace-root resolution)", mountPath)
	fsShare, err := session.Mount(mountPath)
	if err != nil {
		return fmt.Errorf("mount %q: %w", mountPath, err)
	}
	defer fsShare.Umount()
	fsShare = fsShare.WithContext(ctx)
	fmt.Println("    mount OK")

	name := normalizeRel(cfg.relPath)
	if name == "" {
		// No path given — just prove the share root is browsable.
		step("ReadDir of share root")
		ents, err := fsShare.ReadDir(".")
		if err != nil {
			return fmt.Errorf("readdir share root: %w", err)
		}
		printEntries(ents)
		return nil
	}

	// Case B: stat a path that may cross a DFS link. With the fix this
	// follows the link referral; without it, STATUS_PATH_NOT_COVERED.
	step("Stat %q  (Case B: link-crossing path resolution)", name)
	info, err := fsShare.Stat(name)
	if err != nil {
		return fmt.Errorf("stat %q: %w", name, err)
	}
	fmt.Printf("    stat OK: name=%q size=%d dir=%v mode=%v\n", info.Name(), info.Size(), info.IsDir(), info.Mode())

	if info.IsDir() {
		step("ReadDir %q", name)
		ents, err := fsShare.ReadDir(name)
		if err != nil {
			return fmt.Errorf("readdir %q: %w", name, err)
		}
		printEntries(ents)
		return nil
	}

	if cfg.nRead <= 0 {
		return nil
	}
	step("Read first %d bytes of %q", cfg.nRead, name)
	f, err := fsShare.Open(name)
	if err != nil {
		return fmt.Errorf("open %q: %w", name, err)
	}
	defer f.Close()

	buf := make([]byte, cfg.nRead)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("read %q: %w", name, err)
	}
	fmt.Printf("    read OK: %d bytes\n", n)
	fmt.Printf("    preview: %q\n", preview(buf[:n]))
	return nil
}

// normalizeRel converts a user-supplied path to the backslash, no-leading-
// separator form the share API expects ("." stays as the root marker).
func normalizeRel(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.Trim(p, `\`)
	return p
}

func printEntries(ents []os.FileInfo) {
	fmt.Printf("    %d entries:\n", len(ents))
	for i, e := range ents {
		if i >= 20 {
			fmt.Printf("    ... (%d more)\n", len(ents)-20)
			break
		}
		kind := "file"
		if e.IsDir() {
			kind = "dir "
		}
		fmt.Printf("      [%s] %-40s %d\n", kind, e.Name(), e.Size())
	}
}

func preview(b []byte) string {
	const max = 120
	s := string(b)
	if len(s) > max {
		s = s[:max] + "…"
	}
	// Keep it single-line and printable-ish.
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	return s
}

func step(format string, args ...any) {
	fmt.Printf("==> "+format+"\n", args...)
}
