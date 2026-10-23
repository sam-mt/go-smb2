package dfsc

import "testing"

// FuzzDecodeReferralResponse guards the decoder of the referral buffer, which
// comes straight from the server: no input may make it panic.
func FuzzDecodeReferralResponse(f *testing.F) {
	for _, tc := range fuzzSeeds() {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		resp, err := DecodeReferralResponse(b)
		if err == nil && resp == nil {
			t.Fatal("nil response without error")
		}
	})
}

// fuzzSeeds are valid responses for the fuzzer to mutate.
func fuzzSeeds() [][]byte {
	return [][]byte{
		buildResponse(24, HeaderFlagStorageServers,
			v4Target(0, 0, 300, `\ns\dfs\link`, "", `\backing\share`),
			v4Target(0, 0, 300, `\ns\dfs\link`, "", `\backing2\share`)),
		buildResponse(14, HeaderFlagReferralServers|HeaderFlagStorageServers,
			v4Target(ServerTypeRoot, 0, 300, `\ns\dfs`, "", `\root\dfs`)),
		{0, 0, 1},
	}
}
