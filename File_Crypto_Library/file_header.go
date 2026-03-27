package filecryptolibrary

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

func Read_Header(file *os.File) []byte {
	// Reading raw 17 bytes (4 bytes magic + 1 byte version + 8 bytes IV + 4 bytes ChunkSize)
	raw := [17]byte{}
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

	IV := raw[5:13]

	chunkSize := binary.BigEndian.Uint32(raw[13:17])

	Header.IV = IV
	Header.ChunkSize = chunkSize

	return &Header, nil
}

// This function parses structed header to raw header (for writing to files header)
func Parse_Header(header *Crypt_File_Header) ([]byte, error) {
	// Checking if header is nil
	if header == nil {
		return nil, fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_PARSE_HEADER_CALL]")
	}

	if header.IV == nil {
		return nil, fmt.Errorf("Error occurred, error name: [FILE_CRYPTO_INVALID_PARSE_HEADER_CALL]")
	}

	raw := [17]byte{}

	// Writing four bytes of magic
	for i := 0; i < 4; i++ {
		raw[i] = magic_header[i]
	}

	// Writing version to raw
	raw[4] = FILE_CRYPTO_VERSION

	// Writing IV to raw
	copy(raw[5:13], header.IV)

	// Converting ChunkSize to binary format
	ChunkSize_binary := [4]byte{}
	binary.BigEndian.PutUint32(ChunkSize_binary[:], header.ChunkSize)

	// Writing ChunkSize_binary to raw
	copy(raw[13:], ChunkSize_binary[:])

	// Raw header builded, returning raw header
	return raw[:], nil
}

func Write_Header(raw []byte, file *os.File) bool {
	// Writing raw 17 bytes (4 bytes magic + 1 byte version + 8 bytes IV + 4 bytes ChunkSize)
	_, err := file.Write(raw)
	if err != nil {
		return false
	}

	return true
}
