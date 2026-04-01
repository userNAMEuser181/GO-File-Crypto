package filecryptolibrary

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

func Read_Header(file *os.File) []byte {
	// Reading raw 53 bytes (4 bytes magic + 1 byte version + 12 bytes nonce + 4 bytes ChunkSize + 32 bytes HKDF_Salt)
	raw := [53]byte{}
	r, err := file.Read(raw[:])
	if err != nil {
		return nil
	}
	if r != len(raw) {
		return []byte{byte(0x03)} // 0x03 Number of error to FILE_CRYPTO_INVALID_FILE_HEADER_SIZE
	}

	return raw[:]
}

func Parse_Raw_Header(raw []byte) (*Crypt_File_Header, error) {
	// Grabbing magic from raw
	magic := raw[:4]

	// Checking if magic from raw equal with original magic
	if !bytes.Equal(magic, magic_header[:]) {
		return nil, fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_FILE_HEADER]")
	}

	// Checking version with max, min versions setted in types.go
	version := raw[4]
	if version < FILE_CRYPTO_MIN_VERSION || version > FILE_CRYPTO_MAX_VERSION {
		return nil, fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_FILE_VERSION]")
	}

	// Version and magic are ok, parsing main data and putting it to Header struct
	Header := Crypt_File_Header{}

	Nonce := raw[5:17]

	chunkSize := binary.BigEndian.Uint32(raw[17:21])

	Salt := raw[21:]

	Header.Nonce = Nonce
	Header.ChunkSize = chunkSize
	Header.Salt = Salt

	return &Header, nil
}

// This function parses structed header to raw header (for writing to files header)
func Parse_Header(header *Crypt_File_Header) ([]byte, error) {
	// Checking if header is nil
	if header == nil {
		return nil, fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_PARSE_HEADER_CALL]")
	}

	if header.Nonce == nil {
		return nil, fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_PARSE_HEADER_CALL]")
	}

	raw := [53]byte{}

	// Writing four bytes of magic
	for i := 0; i < 4; i++ {
		raw[i] = magic_header[i]
	}

	// Writing version to raw
	raw[4] = FILE_CRYPTO_VERSION

	// Writing IV to raw
	copy(raw[5:17], header.Nonce)

	// Converting ChunkSize to binary format
	ChunkSize_binary := [4]byte{}
	binary.BigEndian.PutUint32(ChunkSize_binary[:], header.ChunkSize)

	// Writing ChunkSize_binary to raw
	copy(raw[17:21], ChunkSize_binary[:])

	// Writing HKDF_Salt to raw
	copy(raw[21:], header.Salt)

	// Raw header builded, returning raw header
	return raw[:], nil
}

func Write_Header(raw []byte, file *os.File) bool {
	// Writing raw 53 bytes (4 bytes magic + 1 byte version + 12 bytes nonce + 4 bytes ChunkSize + 32 bytes HKDF_Salt)
	_, err := file.Write(raw)
	if err != nil {
		return false
	}

	return true
}
