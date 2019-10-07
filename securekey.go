package main

const (
	secureKeyNonceSize = 64
)

func getSecureKey() (string, error) {
	return fw.NonceWithSize(secureKeyNonceSize)
}
