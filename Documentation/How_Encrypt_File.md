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
        UseIV:     false,     /* you can change to true, if want file-encryption fast (but nonces be not unique) */
		ChunkSize: 1024 * 64, /* you can change ChunkSize to your own */
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

## Pros and cons of using HKDF to derive nonces (UseIV : false in code)

### Pros
HKDF-SHA256 is good and widely used.

Salt: Salt is adding uniqueness.

Security: it making harder to crack file
### Cons
Probably High CPU using: HKDF (or HMAC-SHA256) adds extra computation, so it may increase CPU using.

Slow: High CPU using can to slow process of encrypting/decrypting file.

### With HKDF:
```text
[DEBUG]: NONCE OF CHUNK 1 IS { 21 78 fc 9b c8 a4 35 1c 36 cc c9 ce }
[DEBUG]: NONCE OF CHUNK 2 IS { dc 2a 32 59 7d af e9 a3 b7 b0 49 60 }
[DEBUG]: NONCE OF CHUNK 3 IS { f6 50 0f 36 d4 82 c5 86 18 01 dd 14 }
[DEBUG]: NONCE OF CHUNK 4 IS { 14 96 a2 dc f8 91 bb 55 5e 4c 90 c9 }
[DEBUG]: NONCE OF CHUNK 5 IS { e2 fa aa b1 a1 81 f1 18 c1 51 3a 53 }
[DEBUG]: NONCE OF CHUNK 6 IS { a4 2a 4e 66 12 25 58 ec 01 46 bf 89 }
[DEBUG]: NONCE OF CHUNK 7 IS { eb 8f f9 99 b1 3a 1e 2d 5c f9 24 af }
[DEBUG]: NONCE OF CHUNK 8 IS { 99 ae b3 5a 50 c7 7d 01 bb 4f bd f9 }
[DEBUG]: NONCE OF CHUNK 9 IS { b9 75 c6 dd 5d cc 21 eb ea b4 e5 1e }
[DEBUG]: NONCE OF CHUNK 10 IS { 21 d5 14 ee 22 3d 82 3d a8 04 bd ad }
```

### With Counter Mode (UseIV : true):
```text
[DEBUG]: NONCE OF CHUNK 1 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 01 }
[DEBUG]: NONCE OF CHUNK 2 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 02 }
[DEBUG]: NONCE OF CHUNK 3 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 03 }
[DEBUG]: NONCE OF CHUNK 4 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 04 }
[DEBUG]: NONCE OF CHUNK 5 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 05 }
[DEBUG]: NONCE OF CHUNK 6 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 06 }
[DEBUG]: NONCE OF CHUNK 7 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 07 }
[DEBUG]: NONCE OF CHUNK 8 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 08 }
[DEBUG]: NONCE OF CHUNK 9 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 09 }
[DEBUG]: NONCE OF CHUNK 10 IS { 94 b4 11 fb fb 22 5b b9 00 00 00 0a }
```
