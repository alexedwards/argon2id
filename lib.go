// Package lambda_argon provides a convenient wrapper around Go's
// golang.org/x/crypto/argon2 implementation, making it simpler to
// securely hash and verify passwords using the Argon2id algorithm
// while running on AWS Lambda. Cryptographically-secure and randomized
// salts are used by default.
package lambda_argon

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
	ErrInvalidHashFormat        = errors.New("lambda_argon: invalid hash format")           // returned if the provided hash isn't in the expected format.
	ErrUnsupportedArgonVersion  = errors.New("lambda_argon: unsupported version of argon2") // returned if the provided hash was created using an unsupported variant of Argon2.
	ErrNonMatchingArgonVersions = errors.New("lambda_argon: argon2 versions do not match")  // returned if the provided hash was created using a different version of Argon2.
	ErrPasswordTooShort         = errors.New("lambda_argon: password is too short. Please see MinPasswordLength")
	ErrPasswordTooLong          = errors.New("lambda_argon: password is too long. Please see MaxPasswordLength")
)

const MaxPasswordLength = 128
const MinPasswordLength = 12

// lambdaParams have been optimized to execute on a base AWS Lambda instance
// with default memory and CPU settings. The total hash time should take around
// a second to finish on Lambda. 64MB of memory is required to execute the hashing
// function in addition to your normal lambda memory requirements.
var lambdaParams = &params{
	Memory:      64 * 1024, // 64MB of memory is required to perform this hash
	Iterations:  15,
	Parallelism: 4,
	SaltLength:  64,
	KeyLength:   512,
}

// params describes the input parameters used by the Argon2id algorithm.
// For guidance and an outline process for choosing appropriate parameters see
// https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4
type params struct {
	Memory      uint32 // The amount of memory used by the algorithm (in kibibytes).
	Iterations  uint32 // The number of iterations over the memory.
	Parallelism uint8  // The number of threads (or lanes) used by the algorithm. Recommended value is between 1 and runtime.NumCPU().
	SaltLength  uint32 // Length of the random salt. 16 bytes is recommended for password hashing.
	KeyLength   uint32 // Length of the generated key. 16 bytes or more is recommended.
}

// createHash returns an Argon2id hash of a plain-text password using the
// provided algorithm parameters. The returned hash follows the format used by
// the Argon2 reference C implementation and contains the base64-encoded Argon2id d
// derived key prefixed by the salt and parameters. A sample value is below:
//
//		$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
//
func createHash(password string, params *params) (hash string, err error) {
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

// checkHash is like comparePasswordAndHash, except it also returns the params that the hash was created
// with. This can be useful if you want to update your hash params over time (which you should).
func checkHash(password, hash string) (match bool, params *params, err error) {
	params, salt, key, err := decodeHash(hash)
	if err != nil {
		return false, nil, err
	}

	otherKey := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	keyLen := int32(len(key))
	otherKeyLen := int32(len(otherKey))

	if subtle.ConstantTimeEq(keyLen, otherKeyLen) == 0 {
		return false, params, nil
	}
	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, params, nil
	}
	return false, params, nil
}

// comparePasswordAndHash performs a constant-time comparison between a plain-text
// password and Argon2id hash, using the parameters and salt contained in the hash.
// It returns true if they match, otherwise it returns false.
func comparePasswordAndHash(password, hash string) (match bool, err error) {
	match, _, err = checkHash(password, hash)
	return match, err
}

// decodeHash expects a hash created from this package, and parses it to
// return the params used to create it, as well as the salt and key (password hash).
func decodeHash(hash string) (*params, []byte, []byte, error) {
	hashParams := strings.Split(hash, "$")
	if len(hashParams) != 6 {
		return nil, nil, nil, ErrInvalidHashFormat
	}

	if hashParams[1] != "argon2id" {
		return nil, nil, nil, ErrUnsupportedArgonVersion
	}

	var version int
	_, err := fmt.Sscanf(hashParams[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrNonMatchingArgonVersions
	}

	returnParams := &params{}
	_, err = fmt.Sscanf(hashParams[3], "m=%d,t=%d,p=%d", &returnParams.Memory, &returnParams.Iterations, &returnParams.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(hashParams[4])
	if err != nil {
		return nil, nil, nil, err
	}
	returnParams.SaltLength = uint32(len(salt))

	key, err := base64.RawStdEncoding.Strict().DecodeString(hashParams[5])
	if err != nil {
		return nil, nil, nil, err
	}
	returnParams.KeyLength = uint32(len(key))

	return returnParams, salt, key, nil
}

// Hash accepts a string and hashes it using cryptographically-secure defaults.
// The secure hash is returned as a string and is secure to store inside your database.
// The hash contains the hash of the password as well as the hashing parameters used.
func Hash(password string) (string, error) {
	err := verifyPasswordRequirements(password)
	if err != nil {
		return "", err
	}

	return createHash(password, lambdaParams)
}

// Match compares a user password input against a known hash value to see if they're equal.
// The hash input should come from your database and the password input from the user.
func Match(password, hash string) (bool, error) {
	err := verifyPasswordRequirements(password)
	if err != nil {
		return false, err
	}

	return comparePasswordAndHash(password, hash)
}

func verifyPasswordRequirements(password string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}

	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}

	return nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
