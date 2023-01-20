package lambda_argon

import (
	"errors"
	"github.com/jgroeneveld/trial/assert"
	"math/rand"
	"regexp"
	"testing"
	"time"
)

const (
	shortPassword = "pa$$word"
	otherPassword = "otherPa$$word"
)

var longPassword = generateRandomString(int(lambdaParams.KeyLength) * 2)
var goodPassword = generateRandomString(MaxPasswordLength)

func TestCreateHash(t *testing.T) {
	hashRegex, err := regexp.Compile(`^\$argon2id\$v=19\$m=65536,t=15,p=4\$[A-Za-z0-9+/]{86}\$[A-Za-z0-9+/]{683}$`)
	assert.Nil(t, err)

	shortHash1, err := createHash(shortPassword, lambdaParams)
	assert.Nil(t, err)

	shortHash2, err := createHash(shortPassword, lambdaParams)
	assert.Nil(t, err)

	longHash1, err := createHash(longPassword, lambdaParams)
	assert.Nil(t, err)

	longHash2, err := createHash(longPassword, lambdaParams)
	assert.Nil(t, err)

	t.Run("verify hash output matches expected regex for short password", func(t *testing.T) {
		assert.True(t, hashRegex.MatchString(shortHash1))
	})

	t.Run("verify same password produces different hashes for short password", func(t *testing.T) {
		assert.NotEqual(t, shortHash1, shortHash2)
	})

	t.Run("verify hash output matches expected regex for long password", func(t *testing.T) {
		assert.True(t, hashRegex.MatchString(longHash1))
	})

	t.Run("verify same password produces different hashes for long password", func(t *testing.T) {
		assert.NotEqual(t, longHash1, longHash2)
	})
}

func TestCheckHash(t *testing.T) {
	shortHash, err := createHash(shortPassword, lambdaParams)
	assert.Nil(t, err)

	longHash, err := createHash(longPassword, lambdaParams)
	assert.Nil(t, err)

	t.Run("verify checkHash works for short password / hash", func(t *testing.T) {
		ok, shortParams, checkErr := checkHash(shortPassword, shortHash)
		assert.Nil(t, checkErr)
		assert.True(t, ok)
		assert.Equal(t, *shortParams, *lambdaParams)
	})
	t.Run("verify checkHash works for long password / hash", func(t *testing.T) {
		ok, longParams, checkErr := checkHash(longPassword, longHash)
		assert.Nil(t, checkErr)
		assert.True(t, ok)
		assert.Equal(t, *longParams, *lambdaParams)
	})

	testPass := "bug"
	testHash := "$argon2id$v=19$m=65536,t=1,p=2$UDk0zEuIzbt0x3bwkf8Bgw$ihSfHWUJpTgDvNWiojrgcN4E0pJdUVmqCEdRZesx9tE"

	t.Run("verify checkHash with hard coded values", func(t *testing.T) {
		ok, _, checkErr := checkHash(testPass, testHash)
		assert.True(t, ok)
		assert.Nil(t, checkErr)
	})
	t.Run("verify checkHash fails with tampered hash value", func(t *testing.T) {
		tamperedHash := testHash[:len(testHash)-1] + "F" // changed one last character of the hash to an invalid value
		ok, _, checkErr := checkHash(testPass, tamperedHash)
		assert.False(t, ok)
		assert.NotNil(t, checkErr)
	})

	t.Run("verify err when using wrong argon variant", func(t *testing.T) {
		// Hash contains wrong variant
		_, _, checkErr := checkHash("pa$$word", "$argon2i$v=19$m=65536,t=1,p=2$mFe3kxhovyEByvwnUtr0ow$nU9AqnoPfzMOQhCHa9BDrQ+4bSfj69jgtvGu/2McCxU")
		assert.True(t, errors.Is(checkErr, ErrUnsupportedArgonVersion))
	})
}

func TestComparePasswordAndHash(t *testing.T) {
	shortPasswordHash, err := createHash(shortPassword, lambdaParams)
	assert.Nil(t, err)

	longPasswordHash, err := createHash(longPassword, lambdaParams)
	assert.Nil(t, err)

	t.Run("verify compare with correct short password", func(t *testing.T) {
		match, compareErr := comparePasswordAndHash(shortPassword, shortPasswordHash)
		assert.Nil(t, compareErr)
		assert.True(t, match)
	})
	t.Run("verify err with wrong password for short password hash", func(t *testing.T) {
		match, compareErr := comparePasswordAndHash(otherPassword, shortPasswordHash)
		assert.Nil(t, compareErr)
		assert.False(t, match)
	})
	t.Run("verify compare with correct long password", func(t *testing.T) {
		match, compareErr := comparePasswordAndHash(longPassword, longPasswordHash)
		assert.Nil(t, compareErr)
		assert.True(t, match)
	})
	t.Run("verify err with wrong password for long password", func(t *testing.T) {
		match, compareErr := comparePasswordAndHash(otherPassword, longPasswordHash)
		assert.Nil(t, compareErr)
		assert.False(t, match)
	})
}

func TestDecodeHash(t *testing.T) {
	shortHash, err := createHash(shortPassword, lambdaParams)
	assert.Nil(t, err)

	longHash, err := createHash(longPassword, lambdaParams)
	assert.Nil(t, err)

	shortParams, shortSalt, shortKey, err := decodeHash(shortHash)
	assert.Nil(t, err)

	longParams, longSalt, longKey, err := decodeHash(longHash)
	assert.Nil(t, err)

	t.Run("verify shortParams returned are correct", func(t *testing.T) {
		assert.Equal(t, *shortParams, *lambdaParams)
	})
	t.Run("verify shortSalt length is correct", func(t *testing.T) {
		assert.Equal(t, uint32(len(shortSalt)), lambdaParams.SaltLength)
	})
	t.Run("verify shortKey length is correct", func(t *testing.T) {
		assert.Equal(t, uint32(len(shortKey)), lambdaParams.KeyLength)
	})

	t.Run("verify longParams returned are correct", func(t *testing.T) {
		assert.Equal(t, *longParams, *lambdaParams)
	})
	t.Run("verify longSalt length is correct", func(t *testing.T) {
		assert.Equal(t, uint32(len(longSalt)), lambdaParams.SaltLength)
	})
	t.Run("verify longKey length is correct", func(t *testing.T) {
		assert.Equal(t, uint32(len(longKey)), lambdaParams.KeyLength)
	})
}

func TestHash(t *testing.T) {
	t.Run("verify password hashes without error", func(t *testing.T) {
		goodHash, hashErr := Hash(goodPassword)
		assert.Nil(t, hashErr)
		assert.NotEqual(t, "", goodHash)
	})
}

func TestMatch(t *testing.T) {
	t.Run("verify password matches without error", func(t *testing.T) {
		goodHash, hashErr := Hash(goodPassword)
		assert.Nil(t, hashErr)
		assert.NotEqual(t, "", goodHash)

		match, matchErr := Match(goodPassword, goodHash)
		assert.Nil(t, matchErr)
		assert.True(t, match)
	})
}

func TestVerifyPasswordRequirements(t *testing.T) {
	t.Run("verify error when password is below minimum", func(t *testing.T) {
		err := verifyPasswordRequirements(generateRandomString(MinPasswordLength - 1))
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrPasswordTooShort))
	})
	t.Run("verify error when password is above maximum", func(t *testing.T) {
		err := verifyPasswordRequirements(generateRandomString(MaxPasswordLength + 1))
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrPasswordTooLong))
	})
	t.Run("verify no error when input is minimum", func(t *testing.T) {
		err := verifyPasswordRequirements(generateRandomString(MinPasswordLength))
		assert.Nil(t, err)
	})
	t.Run("verify no error when input is maximum", func(t *testing.T) {
		err := verifyPasswordRequirements(generateRandomString(MaxPasswordLength))
		assert.Nil(t, err)
	})
}

func generateRandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}
