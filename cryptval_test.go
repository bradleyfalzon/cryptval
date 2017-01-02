package cryptval_test

import (
	"database/sql"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/bradleyfalzon/cryptval"
	_ "github.com/mattn/go-sqlite3"
)

const TestDB = "./cryptval-test.db"

// TestCryptVal tests the end to end encryption and decryption process
// works with database/sql.
func TestCryptVal(t *testing.T) {
	_ = os.Remove(TestDB) // doesn't matter if remove fails
	defer os.Remove(TestDB)

	db, err := sql.Open("sqlite3", TestDB)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec("CREATE TABLE cv (name text);")
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}

	key := [32]byte{1}
	plaintext := []byte("some-secret")
	encrypt := cryptval.New(cryptval.NewGCM256(key)).EncryptBytes(plaintext)

	_, err = db.Exec("INSERT INTO cv (name) VALUES (?)", encrypt)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}

	decrypt := cryptval.New(cryptval.NewGCM256(key))
	err = db.QueryRow("SELECT name FROM cv").Scan(decrypt)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}

	if !reflect.DeepEqual(decrypt.Plaintext, plaintext) {
		t.Errorf("Failed to encrypt+decrypt\nhave %q\nwant %q", decrypt.Plaintext, plaintext)
	}
}

type mockCipher struct{}

func (mockCipher) Encrypt([]byte) ([]byte, error) { return []byte{0, 0, 1}, nil }
func (mockCipher) Decrypt([]byte) ([]byte, error) { return []byte{0, 0, 2}, nil }

func TestBytesValue(t *testing.T) {
	cv := cryptval.New(mockCipher{}).EncryptBytes([]byte("top-secret"))

	have, err := cv.Value()
	if err != nil {
		t.Fatal("unexpected error from value: ", err)
	}
	if want := []byte("AAAB"); !reflect.DeepEqual(have, want) {
		t.Errorf("Failed to encrypt\nhave %q\nwant %q", have, want)
	}
}

func TestBytesScan(t *testing.T) {
	cv := cryptval.New(mockCipher{})

	err := cv.Scan([]byte("AAAC"))
	if err != nil {
		t.Fatal("unexpected error from scan: ", err)
	}
	if want := []byte{0, 0, 2}; !reflect.DeepEqual(cv.Plaintext, want) {
		t.Errorf("Failed to decrypt\nhave %q\nwant %q", cv.Plaintext, want)
	}
}
