package sbpx_test

// diff package to circumvent cyclic-import err

import (
	"testing"

	"github.com/gerardmrk/sbpx"
	"github.com/gerardmrk/sbpx/hasher"
)

var pswd = []byte(`apU3o9qxw@Z4#^r7U!Y!&Eo8B^NfxgUy@Jm*ZGJ%R#dfWpi3Li6YvT55dEaW`)

var params = sbpx.Params{
	Memory:      255,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  18,
	KeyLength:   35,
}

var hsh, _ = hasher.New(params)
var _enc string //nolint

func BenchmarkEncodeToString(b *testing.B) {
	b.ReportAllocs()
	var enc string
	var err error
	for n := 0; n < b.N; n++ {
		enc, err = sbpx.EncodeToString(pswd, params)
		if err != nil {
			b.Errorf("yikes %+v\n", err)
		}
		// prevent false positives from compiler optimisations.
		_enc = enc
	}
}

func BenchmarkEncodeToStringWithSBPool(b *testing.B) {
	b.ReportAllocs()
	var enc string
	var err error
	for n := 0; n < b.N; n++ {
		enc, err = hsh.EncodeToString(pswd)
		if err != nil {
			b.Errorf("yikes %+v\n", err)
		}
		// prevent false positives from compiler optimisations.
		_enc = enc
	}
}
