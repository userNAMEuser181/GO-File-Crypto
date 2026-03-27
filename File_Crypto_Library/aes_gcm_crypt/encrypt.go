package aesgcmcrypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// AES-GCM Encrypting
func Encrypt(key, nonce, plaintext, aad []byte) ([]byte, int) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, FILE_CRYPTO_INVALID_KEY_SIZE
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, FILE_CRYPTO_INVALID_KEY
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, FILE_CRYPTO_BLOCK_NOT_FOR_GCM
	}
	if len(nonce) != aead.NonceSize() {
		return nil, FILE_CRYPTO_INVALID_NONCE_SIZE
	}
	if aad != nil {
		ct := aead.Seal(nil, nonce, plaintext, aad) // ciphertext || tag
		return ct, 0
	}

	ct := aead.Seal(nil, nonce, plaintext, nil)
	return ct, 0
}
