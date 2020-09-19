package model

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"log"
	"strings"

	logger "github.com/da-moon/go-logger"
	stacktrace "github.com/palantir/stacktrace"
)

// KeyOption ...
type KeyOption func(*Key) error

// Key ...
type Key struct {
	Targets             map[string]string     `json:"targets,omitempty" mapstructure:"targets,omitempty"`
	UUID                string                `json:"uuid,omitempty" mapstructure:"uuid,omitempty"`
	DestinationRootPath string                `json:"destination_root_path,omitempty" mapstructure:"destination_root_path,omitempty"`
	EncryptionKey       string                `json:"encryption_key,omitempty" mapstructure:"encryption_key,omitempty"`
	Nonce               string                `json:"nonce,omitempty" mapstructure:"nonce,omitempty"`
	logger              *logger.WrappedLogger `json:"-"`
}

// WithEncryptionKey sets encryption key
func WithEncryptionKey(arg string) KeyOption {
	return func(s *Key) error {
		if len(arg) != 0 {
			s.EncryptionKey = arg
		}
		return nil
	}
}

// WithNonce sets nonce value
func WithNonce(arg string) KeyOption {
	return func(s *Key) error {
		if len(arg) != 0 {
			s.Nonce = arg
		}
		return nil
	}
}

// WithKeyFile reads encryption key from file
func WithKeyFile(arg string) KeyOption {
	return func(s *Key) error {
		if len(arg) != 0 {
			b, err := ioutil.ReadFile(arg)
			if err != nil {
				err = stacktrace.Propagate(err, " could not read master key file at '%s'. ", arg)
				return err
			}
			s.EncryptionKey = strings.TrimSpace(string(b))
		}
		return nil
	}
}

// NewKey generates a new key
func NewKey(l *log.Logger, uuid string, opts ...KeyOption) (*Key, error) {
	var err error
	if l == nil {
		err = stacktrace.NewError("logger was nil")
		return nil, err
	}
	result := &Key{
		UUID:   uuid,
		logger: logger.NewWrappedLogger(l),
	}
	for _, opt := range opts {
		err = opt(result)
		if err != nil {
			err = stacktrace.Propagate(err, "could not create a new key struct")
			return nil, err
		}
	}
	return result, nil

}

// Sanitize check struct fields for unacceptable values and sets defaults
func (k *Key) Sanitize() error {
	var err error
	if len(k.Nonce) == 0 {
		nonce, err := RandomNonce()
		if err != nil {
			err = stacktrace.Propagate(err, "could not generate random nonce")
			return err
		}
		k.Nonce = hex.EncodeToString(nonce[:])
		k.logger.Warn("[%s] key => generated random nonce '%s'", k.UUID, k.Nonce)
	}
	if len(k.EncryptionKey) == 0 {
		var key [32]byte
		_, err = io.ReadFull(rand.Reader, key[:])
		if err != nil {
			err = stacktrace.Propagate(err, "could not generate random key encryption key")
			return err
		}
		k.EncryptionKey = hex.EncodeToString(key[:])
		k.logger.Warn("[%s] key => encryption key was not provided. using randomly generate key '%s'", k.UUID, k.EncryptionKey)
	}
	return nil
}

// GetEncryptionKey ...
func (k *Key) GetEncryptionKey() ([32]byte, error) {
	var key [32]byte

	decoded, err := hex.DecodeString(k.EncryptionKey)
	if err != nil {
		err = stacktrace.Propagate(err, "could not decode encryption key")
		return [32]byte{}, err
	}
	if len(decoded) != 32 {
		err = stacktrace.NewError("encoded encryption key is %d bytes. We expect 32 byte keys", len(decoded))
		return [32]byte{}, err
	}
	copy(key[:], decoded[:32])
	return key, nil
}

// GetNonce ...
func (k *Key) GetNonce() ([24]byte, error) {
	var nonce [24]byte
	decoded, err := hex.DecodeString(k.Nonce)
	if err != nil {
		err = stacktrace.Propagate(err, "could not decode nonce")
		return [24]byte{}, err
	}
	if len(decoded) != 24 {
		err = stacktrace.NewError("encoded nonce is %d bytes. We expect 32 byte keys", len(decoded))
		return [24]byte{}, err
	}
	copy(nonce[:], decoded[:24])
	return nonce, nil
}

// RandomNonce ...
func RandomNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return [24]byte{}, err
	}
	return nonce, nil
}
