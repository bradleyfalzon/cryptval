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

	key := []byte{0x4f, 0x25, 0xcc, 0xf0, 0xcb, 0x5d, 0xc6, 0x7a, 0x26, 0x1f, 0x13, 0xc4, 0x72, 0x9d, 0x54, 0xc9, 0x9a, 0x9e, 0xfd, 0xf1, 0x6a, 0xe9, 0x45, 0x7f, 0x2e, 0x33, 0xfe, 0xca, 0x80, 0x71, 0x6d, 0x79}
	encrypt := cryptval.NewBytes(cryptval.NewGCM(key))
	encrypt.Bytes = []byte("top-secret")

	_, err = db.Exec("INSERT INTO cv (name) VALUES (?)", encrypt)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}

	decrypt := cryptval.NewBytes(cryptval.NewGCM(key))

	err = db.QueryRow("SELECT name FROM cv").Scan(decrypt)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}

	if !reflect.DeepEqual(encrypt.Bytes, decrypt.Bytes) {
		t.Errorf("Failed to encrypt+decrypt\nwant %q\nhave %q", encrypt.Bytes, decrypt.Bytes)
	}
}

type mockCipher struct{}

func (mockCipher) Encrypt([]byte) ([]byte, error) { return []byte{0, 0, 1}, nil }
func (mockCipher) Decrypt([]byte) ([]byte, error) { return []byte{0, 0, 2}, nil }

func TestBytesValue(t *testing.T) {
	encrypt := cryptval.NewBytes(mockCipher{})
	encrypt.Bytes = []byte("top-secret")

	want := []byte("AAAB")
	have, err := encrypt.Value()
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("Failed to encrypt\nhave %q\nwant %q", have, want)
	}
}

func TestBytesScan(t *testing.T) {
	encrypt := cryptval.NewBytes(mockCipher{})

	want := []byte{0, 0, 2}
	err := encrypt.Scan([]byte("AAAC"))
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	if !reflect.DeepEqual(encrypt.Bytes, want) {
		t.Errorf("Failed to encrypt\nhave %q\nwant %q", encrypt.Bytes, want)
	}
}
