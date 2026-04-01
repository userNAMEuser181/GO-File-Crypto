package filecryptolibrary

import (
	"fmt"
	"os"

	aesgcmcrypto "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library/aes_gcm_crypt"
)

// Main encrypt file function
func Encrypt_File(cryptFile Crypt_File) error {
	if cryptFile.UseIV {
		err := Encrypt_File_Counter(cryptFile)
		return err
	} else {
		err := Encrypt_File_HKDF(cryptFile)
		return err
	}
}

// Encrypt files functions with other options
func Encrypt_File_Counter(cryptFile Crypt_File) error {
	// WARNING: cryptFile.AESkey.Nonce is ignored, here script generating IV (8 bytes) what helps to creating nonces(12 bytes)

	f_in, err := os.Open(cryptFile.Path) // Input file
	if err != nil {
		return err
	}

	f_out, err := os.Create(cryptFile.Path + ".crypted") // Output file
	if err != nil {                                      // File Opening err
		return err
	}

	// In f_out will be written encrypted content, in f_in will be main source

	defer f_out.Close()
	defer f_in.Close()

	fileinfo, err := f_in.Stat()
	if err != nil {
		return err
	}

	// Checking if file is regular file
	if !fileinfo.Mode().IsRegular() {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_FILE_PATH]")
	}

	// Checking if input file has size 0 byte
	if fileinfo.Size() == 0 {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_NO_FILE_CONTENT]")
	}

	IV, code := aesgcmcrypto.GenNonce(12)

	if code != 0 {
		return nil
	}
	nil_salt := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	// Building Crypted File Header struct
	Header := Crypt_File_Header{
		Nonce:     IV,
		Salt:      nil_salt,
		ChunkSize: uint32(cryptFile.ChunkSize),
	}

	// Converting to raw header
	raw_head, err := Parse_Header(&Header)
	if err != nil {
		return err
	}

	// Writing raw header
	if !Write_Header(raw_head, f_out) {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_WRITE_HEADER_FAILED]")
	}

	// Main loop, here we reading chunks of f_in and writing encrypted chunk to f_out
	for plain_chunk, err := range Chunk_Read(f_in, cryptFile.ChunkSize) {
		if err != nil {
			return err
		}

		// Calculating nonce for current chunk_index
		nonce := get_nonce_of_chunk_Counter(IV, uint32(plain_chunk.Index))

		// Encrypting chunk (AAD at moment nil)
		cipher_chunk, errno := aesgcmcrypto.Encrypt(cryptFile.AESkey.Key, nonce, plain_chunk.Data, nil)

		// Checking for errors
		if errno != 0 {
			// Printing error name to screen
			aesgcmcrypto.PrintError(errno)
			return fmt.Errorf("Encryption error occurred")
		}

		// Writing ciphertext || tag
		_, err = f_out.Write(cipher_chunk)
		if err != nil {
			return fmt.Errorf("Writing error")
		}
	}

	// File encrypted, returning error as nil
	return nil
}

func Encrypt_File_HKDF(cryptFile Crypt_File) error {
	// WARNING: cryptFile.AESkey.Nonce is ignored, here script generating Base_Nonce (12 bytes) what helps to creating chunk nonces(12 bytes)

	f_in, err := os.Open(cryptFile.Path) // Input file
	if err != nil {
		return err
	}

	f_out, err := os.Create(cryptFile.Path + ".crypted") // Output file
	if err != nil {                                      // File Opening err
		return err
	}

	// In f_out will be written encrypted content, in f_in will be main source

	defer f_out.Close()
	defer f_in.Close()

	fileinfo, err := f_in.Stat()
	if err != nil {
		return err
	}

	// Checking if file is regular file
	if !fileinfo.Mode().IsRegular() {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_FILE_PATH]")
	}

	// Checking if input file has size 0 byte
	if fileinfo.Size() == 0 {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_NO_FILE_CONTENT]")
	}

	Nonce_base, code := aesgcmcrypto.GenNonce(12)

	if code != 0 {
		return nil
	}

	HKDF_Salt, code := aesgcmcrypto.GenNonce(32)

	if code != 0 {
		return nil
	}

	// Building Crypted File Header struct
	Header := Crypt_File_Header{
		Nonce:     Nonce_base,
		Salt:      HKDF_Salt,
		ChunkSize: uint32(cryptFile.ChunkSize),
	}

	// Converting to raw header
	raw_head, err := Parse_Header(&Header)
	if err != nil {
		return err
	}

	// Writing raw header
	if !Write_Header(raw_head, f_out) {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_WRITE_HEADER_FAILED]")
	}

	// Main loop, here we reading chunks of f_in and writing encrypted chunk to f_out
	for plain_chunk, err := range Chunk_Read(f_in, cryptFile.ChunkSize) {
		if err != nil {
			return err
		}

		// Calculating nonce for current chunk_index
		nonce, err := get_nonce_of_chunk_HKDF(Nonce_base, HKDF_Salt, plain_chunk.Index)

		// Encrypting chunk (AAD at moment nil)
		cipher_chunk, errno := aesgcmcrypto.Encrypt(cryptFile.AESkey.Key, nonce, plain_chunk.Data, nil)

		// Checking for errors
		if errno != 0 {
			// Printing error name to screen
			aesgcmcrypto.PrintError(errno)
			return fmt.Errorf("Encryption error occurred")
		}

		// Writing ciphertext || tag
		_, err = f_out.Write(cipher_chunk)
		if err != nil {
			return fmt.Errorf("Writing error")
		}
	}

	// File encrypted, returning error as nil
	return nil
}
