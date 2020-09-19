package encryptor

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	box "golang.org/x/crypto/nacl/box"

	config "github.com/da-moon/go-dare/internal/config"
	stacktrace "github.com/palantir/stacktrace"
)

// Reader ...
type Reader struct {
	stateLock sync.Mutex
	reader    io.Reader
	nonce     *[24]byte
	sharedKey *[32]byte
	chunkSize int
	buf       *bytes.Buffer
}

// NewReader ...
func NewReader(
	reader io.Reader,
	nonce [24]byte,
	sharedKey *[32]byte,
) *Reader {
	return &Reader{
		buf:       new(bytes.Buffer),
		reader:    reader,
		nonce:     &nonce,
		sharedKey: sharedKey,
		chunkSize: config.DefaultChunkSize,
	}
}

// Read : reads from underlying io.reader
// and encrypts the data as it passes it to given inpout
// do not call directly, use io.Copy
// and dump read data to a bytes.Buffer
func (r *Reader) Read(p []byte) (int, error) {
	var n int
	for {
		buffer := make([]byte, config.DefaultChunkSize)
		bytesRead, err := r.reader.Read(buffer)
		if err == io.EOF {
			// done...
			r.buf.Reset()
			return n, io.EOF
		} else if err != nil {
			err = stacktrace.Propagate(err, "encryptor could not finish reading due to failure of underlying io.reader")
			fmt.Printf("err + %v\n", err)
			return n, err
		}
		r.encrypt(buffer[:bytesRead])
		r.stateLock.Lock()
		nn, err := r.buf.Read(p)
		if err != nil {
			err = stacktrace.Propagate(err, "encryptor could not finish reading due to failure of underlying io.reader")
			fmt.Printf("err + %v\n", err)
			return n, err
		}
		n += nn
		r.stateLock.Unlock()
	}
}

// encrypt ...
func (r *Reader) encrypt(p []byte) error {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	_, err := r.buf.Write(box.SealAfterPrecomputation(nil, p, r.nonce, r.sharedKey))
	if err != nil {
		err = stacktrace.Propagate(err, "could not write the encrypted payload to underlying buffer")
		return err
	}
	// copying first 24 bytes of output as current nonce for nonce chaining
	copy(r.nonce[:], r.buf.Bytes()[:24])
	return nil
}
