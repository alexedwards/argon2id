package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("argon2id: hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("argon2id: incompatible version of argon2")
)

var DefaultParams = &Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func CreateHash(password string, params *Params) (hash string, err error) {
	salt, err := generateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt, b64Key)
	return hash, nil
}

func ComparePasswordAndHash(password, hash string) (match bool, err error) {
	params, salt, key, err := decodeHash(hash)
	if err != nil {
		return false, err
	}

	otherKey := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, nil
	}
	return false, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func decodeHash(hash string) (params *Params, salt, key []byte, err error) {
	vals := strings.Split(hash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	key, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(key))

	return params, salt, key, nil
}
