package aesgcmcrypto

import "fmt"

// ErrNo's constants
const (
	FILE_CRYPTO_INVALID_KEY_SIZE   = 3
	FILE_CRYPTO_INVALID_KEY        = 4
	FILE_CRYPTO_BLOCK_NOT_FOR_GCM  = 5
	FILE_CRYPTO_INVALID_NONCE_SIZE = 6
	FILE_CRYPTO_DECRYPT_FAILED     = 7
)

var error_names = map[int]string{
	FILE_CRYPTO_INVALID_KEY_SIZE:   "FILE_CRYPTO_INVALID_KEY_SIZE",
	FILE_CRYPTO_INVALID_KEY:        "FILE_CRYPTO_INVALID_KEY",
	FILE_CRYPTO_BLOCK_NOT_FOR_GCM:  "FILE_CRYPTO_BLOCK_NOT_FOR_GCM",
	FILE_CRYPTO_INVALID_NONCE_SIZE: "FILE_CRYPTO_INVALID_NONCE_SIZE",
	FILE_CRYPTO_DECRYPT_FAILED:     "FILE_CRYPTO_DECRYPT_FAILED",
}

// ErrNo functions to print error
func PrintError(errno int) {
	if name, exists := error_names[errno]; exists {
		fmt.Printf("Error occurred, error name: [%s]\n", name)
	} else {
		fmt.Printf("Error occurred, unknown error code: %d\n", errno)
	}
}
