package decryptor_test

import (
	"io"

	decryptor "github.com/da-moon/go-dare/internal/decryptor"
)

func init() {
	var _ io.Writer = &decryptor.Writer{}
	var _ io.Reader = &decryptor.Reader{}
}
