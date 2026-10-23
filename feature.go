package smb2

import (
	"github.com/sam-mt/go-smb2/internal/smb2"
)

// client

// clientCapabilities are advertised in the NEGOTIATE request. SMB2_GLOBAL_CAP_DFS
// is included unconditionally — exactly as Windows, cifs.ko, and smbclient do —
// because Windows servers only enable DFS processing (returning
// STATUS_PATH_NOT_COVERED on a DFS link, which drives transparent referral
// following) for clients that negotiated the DFS capability. The per-request
// SMB2_FLAGS_DFS_OPERATIONS header flag is necessary but NOT sufficient: without
// the negotiated capability the server serves the bare DFS reparse stub instead
// of signalling the referral. Advertising it is harmless for non-DFS sessions —
// the server takes no DFS action unless an individual request also carries the
// SMB2_FLAGS_DFS_OPERATIONS flag, which only happens when a Dialer set EnableDFS
// (see dfs_mount.go createFile). Conn.capabilities masks this against the
// server's advertised set, so the bit survives only when the server supports DFS.
const (
	clientCapabilities = smb2.SMB2_GLOBAL_CAP_LARGE_MTU | smb2.SMB2_GLOBAL_CAP_ENCRYPTION | smb2.SMB2_GLOBAL_CAP_DFS
)

var (
	clientHashAlgorithms = []uint16{smb2.SHA512}
	clientCiphers        = []uint16{smb2.AES128GCM, smb2.AES128CCM}
	clientDialects       = []uint16{smb2.SMB311, smb2.SMB302, smb2.SMB300, smb2.SMB210, smb2.SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)

// Mapping strategies that can be used when a reserved character is encountered
// in a file name.
type MapChars int

const (
	// Don't map reserved characters
	MapCharsNone MapChars = 0
	// Map reserved characters using the Services for Mac scheme. This is
	// equivalent to using the 'mapposix' when mounting a volume in Linux.
	MapCharsSFM MapChars = 1
	// Map reserved characters using the Services for Unix scheme. This is
	// equivalent to using 'mapchars' when mounting a volume in Linux.
	MapCharsSFU MapChars = 2
)
