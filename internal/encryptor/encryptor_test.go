package encryptor_test

import (
	"io"

	encryptor "github.com/da-moon/go-dare/internal/encryptor"
)

func init() {
	var _ io.Writer = &encryptor.Writer{}
	var _ io.Reader = &encryptor.Reader{}
}
