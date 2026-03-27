package filecryptolibrary

import (
	"io"
	"os"
)

func Chunk_Read(file *os.File, chunk_size int) func(func(*Chunk, error) bool) {
	return func(yield func(*Chunk, error) bool) {
		// Chunk reader
		chunk_index := 1
		for {
			chunk := make([]byte, chunk_size)

			// Reading current chunk
			r, err := file.Read(chunk)
			if err != nil && err != io.EOF {
				// Sending error to yield
				yield(nil, err)
				return
			}

			if err == io.EOF {
				return // File readed!
			}

			// Sending chunk to yield
			if !yield(&Chunk{Index: chunk_index, Data: chunk[:r]}, nil) {
				return
			}

			chunk_index += 1
		}
	}
}
