package sbpx

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	HasherID      = "argon2id"
	HasherVersion = argon2.Version
)

var (
	// parseable according to the enforced hash format.
	ErrInvalidHashFormat = errors.New("invalid hash format")
	// ErrHashIDMismatch is returned if the hasher name is not the same as HasherID.
	ErrHashIDMismatch = errors.New("hash id mismatch")
	// ErrVersionMismatch is returned if the version is non-parseable.
	ErrVersionMismatch = errors.New("hash version mismatch")
	// ErrParamsMismatched is returned if any one of the parameter field
	// does not match the hasher's parameters.
	ErrParamsMismatch = errors.New("hash params mismatch")
)

type Params struct {
	// Amount of memory used by the algorithm.
	Memory uint32
	// Number of passes over the memory.
	Iterations uint32
	// Number of threads to use.
	Parallelism uint8
	// Length of the generated salt.
	SaltLength uint32
	// Length of the generated key.
	KeyLength uint32
}

func CheckPasswordHashString(password, encoded string) (bool, error) {
	return CheckPasswordHash([]byte(password), []byte(encoded))
}

func CheckPasswordHash(password, encoded []byte) (bool, error) {
	params, salt, key, err := Decode(encoded)
	if err != nil {
		return false, err
	}
	derivedKey := argon2.IDKey(
		password, salt,
		params.Iterations, params.Memory, params.Parallelism, params.KeyLength,
	)
	if subtle.ConstantTimeCompare(key, derivedKey) == 1 {
		return true, nil
	}
	return false, nil
}

func EncodeString(password string, params Params) (string, error) {
	return EncodeToString([]byte(password), params)
}

func Encode(password []byte, params Params) (enc []byte, err error) {
	var encstr string
	encstr, err = EncodeToString(password, params)
	if err != nil {
		return
	}
	enc = []byte(encstr)
	return
}

func EncodeToString(password []byte, params Params) (string, error) {
	start := []byte(fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d",
		HasherID, HasherVersion, params.Memory, params.Iterations, params.Parallelism,
	))
	saltlen := base64.RawStdEncoding.EncodedLen(int(params.SaltLength))
	keylen := base64.RawStdEncoding.EncodedLen(int(params.KeyLength))
	var b strings.Builder
	b.Grow(2 + len(start) + saltlen + keylen)
	if _, err := b.Write(start); err != nil {
		return "", err
	}
	salt := make([]byte, params.SaltLength)
	if err := GenSalt(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(
		password, salt,
		params.Iterations, params.Memory, params.Parallelism, params.KeyLength,
	)
	_, _ = b.WriteRune('$')
	encr := base64.NewEncoder(base64.RawStdEncoding, &b)
	_, _ = encr.Write(salt)
	_ = encr.Close()
	_, _ = b.WriteRune('$')
	encr = base64.NewEncoder(base64.RawStdEncoding, &b)
	_, _ = encr.Write(key)
	_ = encr.Close()
	return b.String(), nil
}

func DecodeString(encoded string) (params Params, salt, key string, err error) {
	params, salt, key, err = DecodeToString([]byte(encoded))
	return
}

func DecodeToString(encoded []byte) (params Params, salt, key string, err error) {
	p, s, k, xerr := Decode(encoded)
	if xerr != nil {
		err = xerr
		return
	}
	params, salt, key = p, string(s), string(k)
	return
}

func Decode(encoded []byte) (params Params, salt, key []byte, err error) {
	scr := bufio.NewScanner(bytes.NewReader(encoded))
	scr.Split(func(data []byte, atEOF bool) (int, []byte, error) {
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
		err = ErrInvalidHashFormat
		return
	}
	// argon2 type check
	if string(tokens[0]) != HasherID {
		err = ErrHashIDMismatch
		return
	}
	// version check
	var version int
	_, xerr := fmt.Sscanf(string(tokens[1]), "v=%d", &version)
	if xerr != nil || version != HasherVersion {
		err = ErrVersionMismatch
		return
	}
	// extract params
	if _, err = fmt.Sscanf(
		string(tokens[2]), "m=%d,t=%d,p=%d",
		&params.Memory, &params.Iterations, &params.Parallelism,
	); err != nil {
		return
	}

	salt = make([]byte, base64.RawStdEncoding.DecodedLen(len(tokens[3])))
	if _, err = base64.RawStdEncoding.Decode(salt, tokens[3]); err != nil {
		return
	}
	params.SaltLength = uint32(len(salt))

	key = make([]byte, base64.RawStdEncoding.DecodedLen(len(tokens[4])))
	if _, err = base64.RawStdEncoding.Decode(key, tokens[4]); err != nil {
		return
	}
	params.KeyLength = uint32(len(key))
	return
}

func GenSalt(dst []byte) error {
	if _, err := rand.Read(dst); err != nil {
		return err
	}
	return nil
}
