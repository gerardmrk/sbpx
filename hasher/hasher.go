package hasher

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/gerardmrk/sbpx"
	"golang.org/x/crypto/argon2"
)

var bpool *strbuilderPool

func init() {
	bpool = &strbuilderPool{}
	bpool.pool.New = func() interface{} {
		return &strings.Builder{}
	}
}

// Hasher is a Argon2 password hasher.
// Its zero value is not safe for use; use the New() func.
type Hasher struct {
	sbpx.Params
	GenSalt    func() ([]byte, error)
	blen       int
	slen       int
	klen       int
	startbytes []byte
}

func New(p sbpx.Params) (*Hasher, error) {
	h := new(Hasher)
	h.Params = p
	h.GenSalt = h._genSalt
	h.startbytes = []byte(fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d",
		sbpx.HasherID, sbpx.HasherVersion, p.Memory, p.Iterations, p.Parallelism,
	))
	h.slen = base64.RawStdEncoding.EncodedLen(int(p.SaltLength))
	h.klen = base64.RawStdEncoding.EncodedLen(int(p.KeyLength))
	// builder.Grow(len) to avoid allocations for each run.
	// +2 for the "$" separators
	h.blen = 2 + len(h.startbytes) + h.slen + h.klen

	return h, nil
}

func (h *Hasher) CheckPasswordHashString(password, encoded string) (bool, error) {
	return h.CheckPasswordHash([]byte(password), []byte(encoded))
}

func (h *Hasher) CheckPasswordHash(password, encoded []byte) (bool, error) {
	salt := make([]byte, h.SaltLength)
	key := make([]byte, h.KeyLength)
	if err := h.Decode(salt, key, encoded); err != nil {
		return false, err
	}
	derivedKey := argon2.IDKey(
		password,
		salt,
		h.Iterations,
		h.Memory,
		h.Parallelism,
		h.KeyLength,
	)
	if subtle.ConstantTimeCompare(key, derivedKey) == 1 {
		return true, nil
	}
	return false, nil
}

// EncodedLen returns the expected bytes length of the encoded hash.
// Use this to precalculate the dest byte array for Hasher.Encode.
func (h *Hasher) EncodedLen() int {
	return h.blen
}

// DecodedLen returns the expected bytes length of the decoded salt and key.
// Use this to precalculate the dest byte arrays for Hasher.Decode.
func (h *Hasher) DecodedLen() (saltlen, keylen int) {
	saltlen = base64.RawStdEncoding.DecodedLen(int(h.SaltLength))
	keylen = base64.RawStdEncoding.DecodedLen(int(h.KeyLength))
	return
}

func (h *Hasher) EncodeString(password string) (string, error) {
	return h.EncodeToString([]byte(password))
}

func (h *Hasher) Encode(encoded, password []byte) error {
	prefix := bytes.NewReader(h.startbytes)
	ln, err := io.ReadFull(prefix, encoded[:len(h.startbytes)])
	if err != nil {
		return err
	}
	salt, err := h.GenSalt()
	if err != nil {
		return err
	}
	key := h.genKey(password, salt)
	encoded[ln], ln = 36, ln+1 // "$"
	var buf bytes.Buffer
	r := bufio.NewWriter(&buf)
	encr := base64.NewEncoder(base64.RawStdEncoding, r)
	_, _ = encr.Write(salt)
	_ = encr.Close()
	_ = r.Flush()
	for i, d := range buf.Bytes() {
		encoded[ln+i] = d
	}
	ln += h.slen
	buf.Reset()
	encoded[ln], ln = 36, ln+1 // "$"
	encr = base64.NewEncoder(base64.RawStdEncoding, r)
	_, _ = encr.Write(key)
	_ = encr.Close()
	_ = r.Flush()
	for i, d := range buf.Bytes() {
		encoded[ln+i] = d
	}
	return nil
}

func (h *Hasher) EncodeToString(password []byte) (enc string, err error) {
	b := bpool.Get()
	b.Grow(h.blen)
	if _, err = b.Write(h.startbytes); err != nil {
		return
	}
	salt, err := h.GenSalt()
	if err != nil {
		return "", err
	}
	key := h.genKey(password, salt)
	_, _ = b.WriteRune('$')
	encr := base64.NewEncoder(base64.RawStdEncoding, b)
	_, _ = encr.Write(salt)
	_ = encr.Close()
	_, _ = b.WriteRune('$')
	encr = base64.NewEncoder(base64.RawStdEncoding, b)
	_, _ = encr.Write(key)
	_ = encr.Close()
	enc = b.String()
	bpool.Put(b)
	return
}

func (h *Hasher) DecodeString(encoded string) (salt, key string, err error) {
	salt, key, err = h.DecodeToString([]byte(encoded))
	return
}

func (h *Hasher) DecodeToString(encoded []byte) (salt, key string, err error) {
	saltdest := make([]byte, h.SaltLength)
	keydest := make([]byte, h.KeyLength)
	if err = h.Decode(saltdest, keydest, encoded); err != nil {
		return
	}
	salt = string(saltdest)
	key = string(keydest)
	return
}

func (h *Hasher) Decode(saltdest, keydest, encoded []byte) (err error) {
	scr := bufio.NewScanner(bytes.NewReader(encoded))
	scr.Split(func(data []byte, atEOF bool) (adv int, tok []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		idx := bytes.IndexByte(data, '$')
		if idx == 0 {
			return 1, nil, nil
		}
		if idx == -1 {
			return len(data), data[0:], nil
		}
		return idx + 1, data[0:idx], nil
	})
	cnt, tokens := 0, make([][]byte, 5)
	for scr.Scan() {
		tokens[cnt] = scr.Bytes()
		cnt++
	}
	if cnt != 5 {
		err = sbpx.ErrInvalidHashFormat
		return
	}
	// argon2 type check
	if string(tokens[0]) != sbpx.HasherID {
		err = sbpx.ErrHashIDMismatch
		return
	}
	// version check
	var version int
	_, xerr := fmt.Sscanf(string(tokens[1]), "v=%d", &version)
	if xerr != nil || version != sbpx.HasherVersion {
		err = sbpx.ErrVersionMismatch
		return
	}
	// extract params
	prms := &sbpx.Params{}
	if _, err = fmt.Sscanf(
		string(tokens[2]), "m=%d,t=%d,p=%d",
		&prms.Memory, &prms.Iterations, &prms.Parallelism,
	); err != nil {
		return
	}
	if _, err = base64.RawStdEncoding.Decode(saltdest, tokens[3]); err != nil {
		return
	}
	prms.SaltLength = uint32(len(saltdest))
	if _, err = base64.RawStdEncoding.Decode(keydest, tokens[4]); err != nil {
		return
	}
	prms.KeyLength = uint32(len(keydest))
	if prms.Memory != h.Memory ||
		prms.Iterations != h.Iterations ||
		prms.SaltLength != h.SaltLength ||
		prms.KeyLength != h.KeyLength {
		err = sbpx.ErrParamsMismatch
		return
	}
	return
}

func (h *Hasher) _genSalt() ([]byte, error) {
	salt := make([]byte, h.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return salt, err
	}
	return salt, nil
}

func (h *Hasher) genKey(password, salt []byte) []byte {
	return argon2.IDKey(
		password, salt,
		h.Iterations, h.Memory, h.Parallelism, h.KeyLength,
	)
}

type strbuilderPool struct {
	pool sync.Pool
}

func (sbp *strbuilderPool) Get() *strings.Builder {
	return sbp.pool.Get().(*strings.Builder)
}

func (sbp *strbuilderPool) Put(b *strings.Builder) {
	b.Reset()
	sbp.pool.Put(b)
}
