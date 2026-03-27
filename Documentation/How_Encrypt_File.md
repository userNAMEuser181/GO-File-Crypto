# Encrypting file

To encrypt your first file, you need have installed library and write this:
```Go
package main

import (
	FCLib "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library"
	AESGCMCrypto "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library/aes_gcm_crypt"
    "fmt"
    "encoding/base64"
)

func main(){
    // Generating key for file
	key_blob, code := AESGCMCrypto.GenKey()
	if code != 0 {
		panic("Error occurred while tried generate AES key (256 bit)")
	}

    // Dont touch this, this is needed struct
    aes_key := FCLib.AES_Key{
		Key: key_blob,
	}

    // Printing key to screen as b64 format
    b64 := base64.StdEncoding.EncodeToString(key_blob)
	fmt.Printf("File key is: '%s'\n", b64)

    // Struct for encrypting/decrypting file
    cryptedFile := FCLib.Crypt_File{
		Path:      "./plain.txt", /* you can change ./plain_txt to other path to file */
		AESkey:    aes_key,
		ChunkSize: 1024 * 1024, /* you can change ChunkSize to your own */
	}

    // Trying to encrypt file
    err := FCLib.Encrypt_File(cryptedFile)

    // Checking for errors
    if err != nil{
        fmt.Printf("Error at encrypting is: %v\n", err)
        return
    }

    fmt.Printf("File encrypted successfuly! Check file '%s.crypted'\n", cryptedFile.Path)
}

```