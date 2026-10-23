package smb2

import (
	"testing"

	"github.com/sam-mt/go-smb2/internal/erref"
)

func TestDFSRouter_OpPath(t *testing.T) {
	t.Run("no prefix (Case B)", func(t *testing.T) {
		d := &dfsRouter{namespacePrefix: `\srv\share`}
		for in, want := range map[string]string{
			`link\sub\f`: `link\sub\f`,
			`\link\f`:    `link\f`,
			// Share root MUST resolve to the empty name, not ".". opPath
			// feeds createFileRaw, which bypasses normPath, so a literal
			// "." reaches Windows verbatim as STATUS_OBJECT_NAME_INVALID.
			``:  ``,
			`.`: ``,
		} {
			if got := d.opPath(in); got != want {
				t.Errorf("opPath(%q)=%q, want %q", in, got, want)
			}
		}
	})
	t.Run("with prefix (Case A)", func(t *testing.T) {
		d := &dfsRouter{namespacePrefix: `\nsroot\dfs`, pathPrefix: `base\dir`}
		for in, want := range map[string]string{
			`f.csv`:     `base\dir\f.csv`,
			`sub\f.csv`: `base\dir\sub\f.csv`,
			``:          `base\dir`,
			`.`:         `base\dir`,
		} {
			if got := d.opPath(in); got != want {
				t.Errorf("opPath(%q)=%q, want %q", in, got, want)
			}
		}
	})
}

// TestDFSRouter_OpPath_ShareRootNeverDot is the regression guard for the
// STATUS_OBJECT_NAME_INVALID bug on plain-mounted DFS-aware shares
// (maestrohub-labs/maestrohub#3323, go-smb2#1). opPath feeds createFileRaw,
// which sends req.Name verbatim without normPath, so a literal "." reaches a
// Windows server as an invalid object name. Every form of "the share root"
// the caller can produce — the empty name and the normPath-untouched "." —
// MUST resolve to the empty string on a no-prefix (plain) share. Samba
// tolerates ".", which is why this is asserted at the unit level rather than
// caught by the Samba-backed behavioural suite.
func TestDFSRouter_OpPath_ShareRootNeverDot(t *testing.T) {
	d := &dfsRouter{namespacePrefix: `\srv\share`} // plain share: pathPrefix == ""
	for _, in := range []string{"", ".", `\`, `/`, `\.`} {
		if got := d.opPath(in); got != "" {
			t.Errorf("opPath(%q)=%q on a plain share; the share root must be the empty name, never %q", in, got, got)
		}
	}
}

// TestDFSPathName guards the name sent with SMB2_FLAGS_DFS_OPERATIONS on a
// DFS share: the server strips the first two components, so the name must
// start with server\share. A share-relative name there opens the wrong
// object (e.g. a file at the root opened the root directory).
func TestDFSPathName(t *testing.T) {
	for _, c := range []struct{ tree, name, want string }{
		{`\\srv\dfsroot`, `file.txt`, `srv\dfsroot\file.txt`},
		{`\\srv\dfsroot`, `link\sub\f`, `srv\dfsroot\link\sub\f`},
		{`\\srv\dfsroot`, ``, `srv\dfsroot`},
		{`\\10.0.0.1\dfsroot`, `a`, `10.0.0.1\dfsroot\a`},
	} {
		if got := dfsPathName(c.tree, c.name); got != c.want {
			t.Errorf("dfsPathName(%q, %q)=%q, want %q", c.tree, c.name, got, c.want)
		}
	}
}

func TestDFSRouter_FullUNC(t *testing.T) {
	d := &dfsRouter{namespacePrefix: `\nsroot\dfs`, pathPrefix: `base`}
	for in, want := range map[string]string{
		`link\f`: `\nsroot\dfs\link\f`,
		`\link`:  `\nsroot\dfs\link`,
		``:       `\nsroot\dfs`,
		`.`:      `\nsroot\dfs`,
	} {
		if got := d.fullUNC(in); got != want {
			t.Errorf("fullUNC(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestIsIPCShare(t *testing.T) {
	for in, want := range map[string]bool{
		`\\server\IPC$`:  true,
		`\\server\ipc$`:  true,
		`\\server\IPC$\`: true,
		`\\server\share`: false,
		`\\server\data`:  false,
	} {
		if got := isIPCShare(in); got != want {
			t.Errorf("isIPCShare(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestIsPathNotCovered(t *testing.T) {
	if !isPathNotCovered(&ResponseError{Code: uint32(erref.STATUS_PATH_NOT_COVERED)}) {
		t.Error("PATH_NOT_COVERED not detected")
	}
	if isPathNotCovered(&ResponseError{Code: uint32(erref.STATUS_BAD_NETWORK_NAME)}) {
		t.Error("BAD_NETWORK_NAME wrongly matched as path-not-covered")
	}
}

func TestIsDFSResolvable(t *testing.T) {
	for _, code := range []erref.NtStatus{
		erref.STATUS_BAD_NETWORK_NAME,
		erref.STATUS_PATH_NOT_COVERED,
		erref.STATUS_DFS_UNAVAILABLE,
	} {
		if !isDFSResolvable(&ResponseError{Code: uint32(code)}) {
			t.Errorf("%v should be DFS-resolvable", code)
		}
	}
	if isDFSResolvable(&ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}) {
		t.Error("ACCESS_DENIED must not be treated as DFS-resolvable")
	}
}
