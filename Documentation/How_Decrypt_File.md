# Decrypting file

To decrypt your first file, you need have installed library and write this:
```Go
package main

import (
    FCLib "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library"
    "fmt"
    "os"
    "bufio"
    "encoding/base64"
)

func main(){
	// Scanning for user input (b64 key)
	scanner := bufio.NewScanner(os.Stdin)

	// Just a prompt
	fmt.Print("Write a file key to decrypt file: ")
	s := ""
	if scanner.Scan() {
		// s = user input
		s = scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		// error handler
		panic(err)
	}

	// Trying convert base64 str to bytes array
	key_blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}

	// Building needed structs
	aes_key := FCLib.AES_Key{
		Key: key_blob,
	}
	encryptedFile := FCLib.Crypt_File{
		Path:   "./plain.txt" + ".crypted", //  you can change "./plain.txt" to every encrypted file path
		AESkey: aes_key,
	}

	// Decrypting file
	err = FCLib.Decrypt_File(encryptedFile)

	// Checking for errors
	if err != nil {
		fmt.Printf("Error at encrypting is: %v\n", err)
		return
	}

	fmt.Printf("File decrypted successfuly! Check file '%s.decrypted'\n", encryptedFile.Path)
}

```