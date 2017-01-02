package cryptval

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"io"
)

// A Cipher encrypts plaintext or decrypts ciphertext.
type Cipher interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

// GCM is a cipher using AES in Galois/Counter Mode.
type GCM struct {
	key []byte
}

// NewGCM256 returns a Cipher using AES-256 in Galois/Counter Mode.
func NewGCM256(key [32]byte) Cipher {
	return GCM{key: key[:]}
}

// Encrypt implements the Cipher interface.
//
// See:
// https://github.com/gtank/cryptopasta/blob/bc3a108a5776376aa811eea34b93383837994340/encrypt.go#L37-L55
func (c GCM) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt implements the Cipher interface.
//
// See:
// https://github.com/gtank/cryptopasta/blob/bc3a108a5776376aa811eea34b93383837994340/encrypt.go#L60-L80
func (c GCM) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
}

// A CryptVal is used to encrypt values for storage in a database, and decrypts
// them, storing the plaintext in Plaintext.
type CryptVal struct {
	cipher    Cipher
	Plaintext []byte
}

// New returns a CryptVal with the chosen cipher.
func New(cipher Cipher) *CryptVal {
	return &CryptVal{cipher: cipher}
}

// EncryptBytes sets plaintext to be encrypted. Returns itself to support fluent
// syntax.
func (s *CryptVal) EncryptBytes(plaintext []byte) *CryptVal {
	s.Plaintext = plaintext
	return s
}

// Value implements the driver Valuer interface by encrypting s.Bytes and
// returning the ciphertext.
func (s CryptVal) Value() (driver.Value, error) {
	ciphertext, err := s.cipher.Encrypt(s.Plaintext)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(buf, ciphertext)
	return buf, nil
}

// Scan implements the Scanner interface by decrypting value and storing the
// result in s.Bytes.
func (s *CryptVal) Scan(value interface{}) error {
	ciphertext := value.([]byte)
	buf := make([]byte, len(ciphertext))
	n, err := base64.StdEncoding.Decode(buf, ciphertext)
	if err != nil {
		return err
	}
	s.Plaintext, err = s.cipher.Decrypt(buf[:n])
	return err
}
