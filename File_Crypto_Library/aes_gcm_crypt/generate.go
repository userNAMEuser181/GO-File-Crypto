package aesgcmcrypto

import (
	"crypto/rand"
	"io"
)

// Generates key
func GenKey() ([]byte, int) {
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, 1
	}
	return k, 0
}

// Generates nonce
func GenNonce(size int) ([]byte, int) {
	n := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		return nil, 2
	}
	return n, 0
}
