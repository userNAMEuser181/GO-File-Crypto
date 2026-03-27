package filecryptolibrary

// Const values to intedify this script, library version and magic
const (
	FILE_CRYPTO_VERSION     = 0x01
	FILE_CRYPTO_MIN_VERSION = 0x01
	FILE_CRYPTO_MAX_VERSION = 0x01
)

// Magic header for files, this is intedifies format of file that you reading
var magic_header = [4]byte{0xC0, 0xF0, 0xC4, 0x78}

type AES_Key struct {
	Key []byte
}

type Crypt_File struct {
	Path      string
	AESkey    AES_Key // VERY NEEDED PARAMETER
	ChunkSize int
}

type Crypt_File_Header struct {
	ChunkSize uint32
	IV        []byte
}

// file_chunk_reader.go struct for chunking files
type Chunk struct {
	Index int
	Data  []byte
}
