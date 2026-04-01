package test

import (
	"testing"

	FCLib "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library"
)

func TestEmptyFile(t *testing.T) {
	cryptedFile := FCLib.Crypt_File{
		Path: "./test_empty.bin",
		// AESkey: aes_key, i will remove aes_key to proof what error catching before crypto operations
	}

	run_decryption(t, nil, cryptedFile)
}
