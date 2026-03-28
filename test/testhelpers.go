package test

import (
	"os"
	"testing"

	FCLib "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library"
)

func run_decryption(t *testing.T, content []byte, cryptedFile FCLib.Crypt_File) {
	t.Run(cryptedFile.Path, func(t *testing.T) {
		file, err := os.Create(cryptedFile.Path)
		if err != nil {
			t.Fatalf("File cannot be creatten, error: %v\n", err)
		}
		if content != nil {
			file.Write(content)
		}

		file.Close()

		err = FCLib.Decrypt_File(cryptedFile)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("Everyting ran successful!")
	})
}
