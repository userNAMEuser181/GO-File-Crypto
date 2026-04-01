package filecryptolibrary

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"

	aesgcmcrypto "github.com/userNAMEuser181/GO-File-Crypto/File_Crypto_Library/aes_gcm_crypt"
)

// Byte function to understand if byte array full of zeroes
func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Main encrypt file function
func Decrypt_File(cryptFile Crypt_File) error {
	f_in, err := os.Open(cryptFile.Path) // Input file (ciphertext content)
	if err != nil {
		return err
	}
	defer f_in.Close()

	// Reading file content size (!! Checking before parsing header, it can occur overflow panic: runtime error: index out of range [0] with length 0 [recovered, repanicked]!!)
	fileinfo, err := f_in.Stat()
	if err != nil {
		return err
	}

	// Checking if file is regular file
	if !fileinfo.Mode().IsRegular() {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_FILE_PATH]")
	}

	// Checking if input file has size 0 byte
	if fileinfo.Size() <= 69 { // 69 because tag size + header at start, if it less or equal to 69 it mean no encrypted file content or invalid size of header
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_NO_ENCRYPTED_FILE_CONTENT]")
	}

	// Reading raw header
	raw := Read_Header(f_in)

	// Parsing raw header
	Header, err := Parse_Raw_Header(raw)
	if err != nil {
		return err
	}

	// Checking for modes, if salt has full of zeroes, then using File_Counter, if File_HKDF then salt will be not full of zeroes
	if isAllZeros(Header.Salt) {
		err := Decrypt_File_Counter(cryptFile)
		return err
	} else {
		err := Decrypt_File_HKDF(cryptFile)
		return err
	}
}

func Decrypt_File_HKDF(cryptFile Crypt_File) error {
	// cryptFile.ChunkSize parameter will be ignored, because crypted file should have it in header
	f_in, err := os.Open(cryptFile.Path) // Input file (ciphertext content)
	if err != nil {
		return err
	}

	var out_path string

	if cryptFile.OUT_Path == "" {
		out_path = cryptFile.Path + ".decrypted"
	} else {
		out_path = cryptFile.OUT_Path
	}

	f_out, err := os.Create(out_path) // Output file (plaintext content)
	if err != nil {
		return err
	}

	// In f_out will be written decrypted data of f_in file encrypted data

	defer f_out.Close()
	defer f_in.Close()

	// Reading raw header
	raw := Read_Header(f_in)
	if raw[0] == 0x03 {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_FILE_HEADER_SIZE]")
	}

	// Parsing raw header
	Header, err := Parse_Raw_Header(raw)
	if err != nil {
		return err
	}

	// Main loop, here we reading encrypted chunks of f_in and writing decrypted chunk to f_out
	for cipher_chunk, err := range Chunk_Read(f_in, int(Header.ChunkSize)+16) /* + 16 because it has tag in ciphertext */ {
		// Checking chunk_reader errors
		if err != nil {
			return err
		}

		// Avoiding errors and checking if readed <= 16
		if len(cipher_chunk.Data) <= 16 {
			return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_CIPHER_CHUNK_SIZE]")
		}

		nonce, err := get_nonce_of_chunk_HKDF(Header.Nonce, Header.Salt, uint64(cipher_chunk.Index))
		if err != nil {
			return err
		}

		// Decrypting chunk (AAD at moment is nil and i know what this is not good)
		plain_chunk, errno := aesgcmcrypto.Decrypt(cryptFile.AESkey.Key, nonce, cipher_chunk.Data, nil)

		// Checking for errors
		if errno != 0 {
			// Printing error name to screen
			aesgcmcrypto.PrintError(errno)
			return fmt.Errorf("Decryption error occurred")
		}

		// Writing decrypted chunk to output file
		_, err = f_out.Write(plain_chunk)
		if err != nil {
			return fmt.Errorf("Writing error")
		}
	}

	// File decrypted, returning error as nil
	return nil
}

func Decrypt_File_Counter(cryptFile Crypt_File) error {
	// cryptFile.ChunkSize parameter will be ignored, because crypted file should have it in header
	f_in, err := os.Open(cryptFile.Path) // Input file (ciphertext content)
	if err != nil {
		return err
	}

	var out_path string

	if cryptFile.OUT_Path == "" {
		out_path = cryptFile.Path + ".decrypted"
	} else {
		out_path = cryptFile.OUT_Path
	}

	f_out, err := os.Create(out_path) // Output file (plaintext content)
	if err != nil {
		return err
	}

	// In f_out will be written decrypted data of f_in file encrypted data

	defer f_out.Close()
	defer f_in.Close()

	// Reading raw header
	raw := Read_Header(f_in)
	if raw[0] == 0x03 {
		return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_FILE_HEADER_SIZE]")
	}

	// Parsing raw header
	Header, err := Parse_Raw_Header(raw)
	if err != nil {
		return err
	}

	// Main loop, here we reading encrypted chunks of f_in and writing decrypted chunk to f_out
	for cipher_chunk, err := range Chunk_Read(f_in, int(Header.ChunkSize)+16) /* + 16 because it has tag in ciphertext */ {
		// Avoiding errors and checking if readed <= 16
		if len(cipher_chunk.Data) <= 16 {
			return fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_CIPHER_CHUNK_SIZE]")
		}

		nonce := get_nonce_of_chunk_Counter(Header.Nonce, uint32(cipher_chunk.Index))

		// Decrypting chunk (AAD at moment is nil and i know what this is not good)
		plain_chunk, errno := aesgcmcrypto.Decrypt(cryptFile.AESkey.Key, nonce, cipher_chunk.Data, nil)

		// Checking for errors
		if errno != 0 {
			// Printing error name to screen
			aesgcmcrypto.PrintError(errno)
			return fmt.Errorf("Decryption error occurred")
		}

		// Writing decrypted chunk to output file
		_, err = f_out.Write(plain_chunk)
		if err != nil {
			return fmt.Errorf("Writing error")
		}
	}

	// File decrypted, returning error as nil
	return nil
}

// Calculates nonce (12 bytes) from 8 byte IV and with chunk_index and with salt
func get_nonce_of_chunk_HKDF(baseNonce, salt []byte, chunkIndex uint64) ([]byte, error) {
	info := []byte("FCLibv0.2:nonce:")
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], chunkIndex)
	info = append(info, idx[:]...)
	return hkdf.Key(sha256.New, baseNonce, salt, string(info), 12)
}

// Calculates nonce (12 bytes) from 8 byte IV and with chunk_index
func get_nonce_of_chunk_Counter(IV []byte, chunk_index uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, IV)
	binary.BigEndian.PutUint32(nonce[8:], chunk_index)
	return nonce
}
