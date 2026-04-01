package filecryptolibrary

// Const values to intedify this script, library version and magic
const (
	FILE_CRYPTO_VERSION     = 0x02
	FILE_CRYPTO_MIN_VERSION = 0x02
	FILE_CRYPTO_MAX_VERSION = 0x02
)

// Magic header for files, this is intedifies format of file that you reading
var magic_header = [4]byte{0xC0, 0xF0, 0xC4, 0x78}

type AES_Key struct {
	Key []byte
}

type Crypt_File struct {
	OUT_Path  string  // Output file path
	Path      string  // Input file path
	AESkey    AES_Key // VERY NEEDED PARAMETER
	ChunkSize int
	UseIV     bool // If useIV is true, then will be called function that generates chunk nonce from iv and counter mode,
	// But if useIV is false it will call function that uses HKDF nonce generation
}

type Crypt_File_Header struct {
	ChunkSize uint32
	Nonce     []byte
	Salt      []byte
}

// file_chunk_reader.go struct for chunking files
type Chunk struct {
	Index uint64
	Data  []byte
}
