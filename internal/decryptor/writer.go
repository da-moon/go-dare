package decryptor

import (
	"io"
	"sync"

	config "github.com/da-moon/go-dare/internal/config"
	"github.com/palantir/stacktrace"
	box "golang.org/x/crypto/nacl/box"
)

// Writer ...
type Writer struct {
	stateLock sync.Mutex
	writer    io.Writer
	nonce     *[24]byte
	sharedKey *[32]byte
	chunkSize int
	buf       []byte
}

// NewWriter ...
func NewWriter(
	writer io.Writer,
	nonce [24]byte,
	sharedKey *[32]byte,
) *Writer {
	return &Writer{
		writer:    writer,
		nonce:     &nonce,
		sharedKey: sharedKey,
		chunkSize: config.DefaultChunkSize,
	}
}

// Write ..
func (d *Writer) Write(p []byte) (n int, err error) {
	err = d.decrypt(p)
	if err != nil {
		return 0, err
	}
	n, err = d.writer.Write(d.buf)
	if err != nil {
		err = stacktrace.Propagate(err, "decryptor could not finish writing due to failure of underlying io.reader")

		return 0, err
	}
	return n, nil
}

// decrypt ...
func (d *Writer) decrypt(p []byte) error {
	d.stateLock.Lock()
	defer d.stateLock.Unlock()
	var ok bool

	d.buf, ok = box.OpenAfterPrecomputation(nil, p, d.nonce, d.sharedKey)
	if !ok {
		err := stacktrace.NewError("box.OpenAfterPrecomputation returned false. can be due to verification failure")
		return err
	}
	// copying first 24 bytes of output as current nonce for nonce chaining
	copy(d.nonce[:], p[:24])
	return nil
}
