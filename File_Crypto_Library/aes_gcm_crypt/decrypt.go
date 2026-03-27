package aesgcmcrypto

import (
	"crypto/aes"
	"crypto/cipher"
)

// AES-GCM Decrypting
func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, int) {
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
		pt, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return nil, FILE_CRYPTO_DECRYPT_FAILED
		}
		return pt, 0
	}

	pt, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, FILE_CRYPTO_DECRYPT_FAILED
	}
	return pt, 0
}
