package decryptor

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
// and encryopts the data as it passes it to given inpout
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
			err = stacktrace.Propagate(err, "decryptor could not finish reading due to failure of underlying io.reader")
			fmt.Printf("err + %v\n", err)
			return n, err
		}
		err = r.decrypt(buffer[:bytesRead])
		if err != nil {
			return 0, err
		}
		r.stateLock.Lock()
		nn, err := r.buf.Read(p)
		if err != nil {
			err = stacktrace.Propagate(err, "decryptor could not finish reading due to failure of underlying io.reader")
			fmt.Printf("err + %v\n", err)
			return n, err
		}
		n += nn
		r.stateLock.Unlock()
	}
}

// decrypt ...
func (r *Reader) decrypt(p []byte) error {
	r.stateLock.Lock()
	defer r.stateLock.Unlock()
	buf, ok := box.OpenAfterPrecomputation(nil, p, r.nonce, r.sharedKey)
	if !ok {
		err := stacktrace.NewError("box.OpenAfterPrecomputation returned false. can be due to verification failure")
		return err
	}
	_, err := r.buf.Write(buf)
	if err != nil {
		err = stacktrace.Propagate(err, "could not write the decrypted payload to underlying buffer")
		return err
	}
	// copying first 24 bytes of output as current nonce for nonce chaining
	copy(r.nonce[:], r.buf.Bytes()[:24])
	return nil
}
