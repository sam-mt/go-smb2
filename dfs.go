package smb2

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/sam-mt/go-smb2/internal/dfsc"
	"github.com/sam-mt/go-smb2/internal/erref"
	"github.com/sam-mt/go-smb2/internal/smb2"
)

// fsctlMaxOutputResponse bounds the referral buffer we ask the server to
// return for FSCTL_DFS_GET_REFERRALS. Referral lists are small (a handful
// of targets, each a short UNC), so 64 KiB is generous and avoids the
// STATUS_BUFFER_OVERFLOW continuation dance that ListSharenames needs for
// large share enumerations.
const fsctlMaxOutputResponse = 64 * 1024

// serverName returns the bare host name of the server this session is
// connected to, suitable for building a `\\server\IPC$` UNC. Any
// host:port form (DialConn is called with an endpoint address) has its
// port stripped — a port has no place in a UNC and some servers reject
// it.
func (c *Session) serverName() string {
	name := c.host
	if name == "" {
		name = c.addr
	}
	if host, _, err := net.SplitHostPort(name); err == nil {
		return host
	}
	return name
}

// effectiveMaxTransactSize mirrors File.maxTransactSize for a fileless
// IOCTL issued on this tree connect (there is no *File to hang it off).
func (fs *Share) effectiveMaxTransactSize() int {
	size := min(int(fs.maxTransactSize), winMaxPayloadSize)
	if fs.conn.capabilities&smb2.SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		if size > singleCreditMaxPayloadSize {
			size = singleCreditMaxPayloadSize
		}
	}
	return size
}

// ioctlFileless issues an SMB2 IOCTL on this tree connect without an open
// file handle, using the 16x0xFF sentinel FileId (the "no open file" id
// that FSCTL_DFS_GET_REFERRALS expects). It mirrors File.ioctl but takes
// no *File, and ORs extraHeaderFlags into the SMB2 header — DFS referral
// requests must carry SMB2_FLAGS_DFS_OPERATIONS. The send path
// (makeRequestResponse) preserves header Flags, so the bit survives onto
// the wire.
func (fs *Share) ioctlFileless(req *smb2.IoctlRequest, extraHeaderFlags uint32) (output []byte, err error) {
	inputSize := 0
	if req.Input != nil {
		inputSize = req.Input.Size()
	}
	payloadSize := max(inputSize+int(req.OutputCount), int(req.MaxOutputResponse+req.MaxInputResponse))

	if fs.effectiveMaxTransactSize() < payloadSize {
		return nil, &InternalError{fmt.Sprintf("payload size %d exceeds max transact size %d", payloadSize, fs.effectiveMaxTransactSize())}
	}

	req.CreditCharge, _, err = fs.borrowCredits(payloadSize)
	if err != nil {
		return nil, err
	}

	// sentinelFileId (defined in tree_conn.go) is the same 16x0xFF handle
	// the DFS IOCTL requires for a fileless operation.
	req.FileId = sentinelFileId
	req.Header().Flags |= extraHeaderFlags

	res, err := fs.sendRecv(smb2.SMB2_IOCTL, req)
	if err != nil {
		// Mirror File.ioctl: a status-bearing response (e.g.
		// STATUS_BUFFER_OVERFLOW) may still carry a usable output buffer.
		r := smb2.IoctlResponseDecoder(res)
		if r.IsInvalid() {
			return nil, err
		}
		return r.Output(), err
	}

	r := smb2.IoctlResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken ioctl response format"}
	}
	return r.Output(), nil
}

// dfsGetReferral issues FSCTL_DFS_GET_REFERRALS for the given UNC path
// against this session's server, over a transient `\IPC$` tree connect,
// and returns the decoded MS-DFSC referral response.
//
// path is the full UNC being resolved (e.g. `\nsroot\dfs\link\sub\file`)
// and is sent verbatim as the MS-DFSC RequestFileName. The request is
// made at referral level 4 first; on STATUS_INVALID_PARAMETER (older
// servers reject level 4) it retries at level 3 then 2. The codec parses
// all of versions 1-4, so a downgraded response still decodes.
func (c *Session) dfsGetReferral(ctx context.Context, path string) (*dfsc.ReferralResponse, error) {
	ipc, err := c.Mount(fmt.Sprintf(`\\%s\IPC$`, c.serverName()))
	if err != nil {
		return nil, fmt.Errorf("dfs: mount IPC$ on %s: %w", c.serverName(), err)
	}
	defer func() { _ = ipc.Umount() }()
	ipc = ipc.WithContext(ctx)

	levels := []uint16{dfsc.MaxReferralLevelV4, dfsc.MaxReferralLevelV3, dfsc.MaxReferralLevelV2}

	var lastErr error
	for _, level := range levels {
		req := &smb2.IoctlRequest{
			CtlCode:           smb2.FSCTL_DFS_GET_REFERRALS,
			MaxInputResponse:  0,
			MaxOutputResponse: fsctlMaxOutputResponse,
			Flags:             smb2.SMB2_0_IOCTL_IS_FSCTL,
			Input: &dfsc.ReferralRequest{
				MaxReferralLevel: level,
				RequestFileName:  path,
			},
		}

		output, ioErr := ipc.ioctlFileless(req, smb2.SMB2_FLAGS_DFS_OPERATIONS)
		if ioErr != nil {
			if isInvalidParameterStatus(ioErr) {
				// Server rejected this referral level — try a lower one.
				lastErr = ioErr
				continue
			}
			return nil, ioErr
		}

		resp, decErr := dfsc.DecodeReferralResponse(output)
		if decErr != nil {
			return nil, fmt.Errorf("dfs: decode referral response for %q: %w", path, decErr)
		}
		return resp, nil
	}

	return nil, fmt.Errorf("dfs: get referral for %q rejected at all referral levels: %w", path, lastErr)
}

// isInvalidParameterStatus reports whether err is an SMB response error
// carrying STATUS_INVALID_PARAMETER — the signal an older DFS server
// gives when it does not support the requested MaxReferralLevel.
func isInvalidParameterStatus(err error) bool {
	var re *ResponseError
	if errors.As(err, &re) {
		return erref.NtStatus(re.Code) == erref.STATUS_INVALID_PARAMETER
	}
	return false
}
