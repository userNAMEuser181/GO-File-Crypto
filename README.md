# GO-File-Crypto
This is project that encrypts files or decrypts encrypted files.

## More about project
I made Library, but planning to create CLI Client.
Encryption mode that i using here, it's AES-256-GCM.
Nonce derives from HKDF or from Counter mode (8 byte of Base_IV and 4 byte of Chunk_Index).

## Requirements
You need have installed Go and install my library. 
To install my library you need execute
```bash
go get github.com/userNAMEuser181/GO-File-Crypto
```
And if you need import my library to code,
then add to your code
```Go
import "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library"
```
And you imported my library! How to use it i will show in documentation.

## How to test this project
You need complete requirements and after write in console this
```bash
go test github.com/userNAMEuser181/GO-File-Crypto/test/ -v
```
And it show output of test scripts.

## TODO
I want rewrite functions Write_Header and Read_Header, so they will read encrypted header and after decrypt it and return 
decrypted raw header or writing encrypted raw header.
Updates will be in summer time.

## Documentation
Follow to folder "Documentation".
