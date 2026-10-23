package smb2

import (
	"errors"
	"testing"

	"github.com/sam-mt/go-smb2/internal/erref"
)

func TestSessionServerName(t *testing.T) {
	cases := []struct {
		name string
		host string
		addr string
		want string
	}{
		{"host without port", "fileserver", "", "fileserver"},
		{"host with port", "fileserver:445", "", "fileserver"},
		{"ipv4 with port", "10.0.0.5:445", "", "10.0.0.5"},
		{"falls back to addr", "", "10.0.0.6:445", "10.0.0.6"},
		{"ipv6 with port", "[fe80::1]:445", "", "fe80::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Session{host: tc.host, addr: tc.addr}
			if got := c.serverName(); got != tc.want {
				t.Errorf("serverName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsInvalidParameterStatus(t *testing.T) {
	if !isInvalidParameterStatus(&ResponseError{Code: uint32(erref.STATUS_INVALID_PARAMETER)}) {
		t.Error("STATUS_INVALID_PARAMETER ResponseError not recognized")
	}
	// Wrapped error must still be detected (the IOCTL path wraps).
	wrapped := errors.Join(errors.New("context"), &ResponseError{Code: uint32(erref.STATUS_INVALID_PARAMETER)})
	if !isInvalidParameterStatus(wrapped) {
		t.Error("wrapped STATUS_INVALID_PARAMETER not recognized")
	}
	// Other statuses and plain errors must not match.
	if isInvalidParameterStatus(&ResponseError{Code: uint32(erref.STATUS_BAD_NETWORK_NAME)}) {
		t.Error("STATUS_BAD_NETWORK_NAME wrongly matched")
	}
	if isInvalidParameterStatus(errors.New("plain")) {
		t.Error("plain error wrongly matched")
	}
	if isInvalidParameterStatus(nil) {
		t.Error("nil wrongly matched")
	}
}
