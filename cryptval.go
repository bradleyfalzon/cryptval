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

type Cipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

type GCM struct {
	key []byte
}

func NewGCM(key []byte) Cipher {
	return GCM{key: key[:]}
}

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

type Bytes struct {
	cipher Cipher
	Bytes  []byte
}

func NewBytes(cipher Cipher) *Bytes {
	return &Bytes{cipher: cipher}
}

// Value implements the driver Valuer interface by encrypting s.Bytes and
// returning the ciphertext.
func (s Bytes) Value() (driver.Value, error) {
	ciphertext, err := s.cipher.Encrypt(s.Bytes)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(buf, ciphertext)
	return buf, nil
}

// Scan implements the Scanner interface by decrypting value and storing the
// result in s.Bytes.
func (s *Bytes) Scan(value interface{}) error {
	ciphertext := value.([]byte)
	buf := make([]byte, len(ciphertext))
	n, err := base64.StdEncoding.Decode(buf, ciphertext)
	if err != nil {
		return err
	}
	s.Bytes, err = s.cipher.Decrypt(buf[:n])
	return err
}
