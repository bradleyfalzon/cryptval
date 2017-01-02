# Introduction

[![Build
Status](https://travis-ci.org/bradleyfalzon/cryptval.svg?branch=master)](https://travis-ci.org/bradleyfalzon/cryptval)
[![GoDoc](https://godoc.org/github.com/bradleyfalzon/cryptval?status.svg)](https://godoc.org/github.com/bradleyfalzon/cryptval)

`cryptval` helps to encrypt and decrypt database values in Go by implementing the `database/sql/.Scanner` and
`database/sql/driver.Valuer` interfaces.

It's goal is to encrypt only a single or a few database fields, such as OAuth tokens for a user, or other sensitive
information. I.e. it's not suitable to store all contents encrypted.

The ciphertext is stored in the database and is base64 encoded, therefore the column's data type must be able to store
this, such as `TEXT`.

The cryptography is copied from https://github.com/gtank/cryptopasta and has the issue outlined: https://github.com/gtank/cryptopasta/issues/14

# Installation

```
go get -u github.com/bradleyfalzon/cryptval
```

# Encrypt Example

```go
key := []byte{0x4f, 0x25, 0xcc, 0xf0, 0xcb, 0x5d, 0xc6, 0x7a, 0x26, 0x1f, 0x13, 0xc4, 0x72, 0x9d, 0x54, 0xc9, 0x9a, 0x9e, 0xfd, 0xf1, 0x6a, 0xe9, 0x45, 0x7f, 0x2e, 0x33, 0xfe, 0xca, 0x80, 0x71, 0x6d, 0x79}
plaintext := []byte("some-secret")
secret := cryptval.New(cryptval.NewGCM256(key)).EncryptBytes(plaintext)

_, err = db.Exec("INSERT INTO cv (secret) VALUES (?)", secret)
if err != nil {
	log.Fatalln("unexpected error:", err)
}
````

# Decrypt Example

```go
key := []byte{0x4f, 0x25, 0xcc, 0xf0, 0xcb, 0x5d, 0xc6, 0x7a, 0x26, 0x1f, 0x13, 0xc4, 0x72, 0x9d, 0x54, 0xc9, 0x9a, 0x9e, 0xfd, 0xf1, 0x6a, 0xe9, 0x45, 0x7f, 0x2e, 0x33, 0xfe, 0xca, 0x80, 0x71, 0x6d, 0x79}
secret := cryptval.New(cryptval.NewGCM256(key))
err := db.QueryRow("SELECT name FROM cv").Scan(name)

if err != nil {
	log.Fatalln("unexpected error:", err)
}
log.Println("secret (plaintext):", secret)
```
