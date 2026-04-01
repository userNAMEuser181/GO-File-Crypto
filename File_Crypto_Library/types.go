package filecryptolibrary

// Const values to intedify this script, library version and magic
const (
<<<<<<< HEAD
	FILE_CRYPTO_VERSION     = 0x01
	FILE_CRYPTO_MIN_VERSION = 0x01
	FILE_CRYPTO_MAX_VERSION = 0x01
=======
	FILE_CRYPTO_VERSION     = 0x02
	FILE_CRYPTO_MIN_VERSION = 0x02
	FILE_CRYPTO_MAX_VERSION = 0x02
>>>>>>> 534ce9f (lib v0.2)
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
<<<<<<< HEAD
=======
	UseIV     bool // If useIV is true, then will be called function that generates chunk nonce from iv and counter mode,
	// But if useIV is false it will call function that uses HKDF nonce generation
>>>>>>> 534ce9f (lib v0.2)
}

type Crypt_File_Header struct {
	ChunkSize uint32
<<<<<<< HEAD
	IV        []byte
=======
	Nonce     []byte
	Salt      []byte
>>>>>>> 534ce9f (lib v0.2)
}

// file_chunk_reader.go struct for chunking files
type Chunk struct {
<<<<<<< HEAD
	Index int
=======
	Index uint64
>>>>>>> 534ce9f (lib v0.2)
	Data  []byte
}
