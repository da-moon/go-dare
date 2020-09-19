package model

import (
	"encoding/hex"
	"fmt"
	"path/filepath"

	files "github.com/da-moon/go-files"
	logger "github.com/da-moon/go-logger"
	primitives "github.com/da-moon/go-primitives"
	stacktrace "github.com/palantir/stacktrace"
)

// EncryptRequest ...
type EncryptRequest struct {
	Targets             map[string]string     `json:"targets,omitempty" mapstructure:"targets,omitempty"`
	UUID                string                `json:"uuid,omitempty" mapstructure:"uuid,omitempty"`
	DestinationRootPath string                `json:"destination_root_path,omitempty" mapstructure:"destination_root_path,omitempty"`
	Key                 [32]byte              `json:"-" `
	Nonce               [24]byte              `json:"-" `
	logger              *logger.WrappedLogger `json:"-" `
}

// NewEncryptRequest adds a target path to encrypt
func (k *Key) NewEncryptRequest(source, destinationRoot, regex string) (*EncryptRequest, error) {
	// src path => dst path
	var err error
	source, err = filepath.Abs(source)
	if err != nil {
		err = stacktrace.Propagate(err, "could not get aboslute path for source path of '%v'", source)
		return nil, err
	}
	key, err := k.GetEncryptionKey()
	if err != nil {
		err = stacktrace.Propagate(err, "could not extract encryption key")
		return nil, err
	}
	nonce, err := k.GetNonce()
	if err != nil {
		err = stacktrace.Propagate(err, "could not extract nonce")
		return nil, err
	}
	r := &EncryptRequest{
		UUID:                k.UUID,
		logger:              k.logger,
		DestinationRootPath: destinationRoot,
		Targets:             make(map[string]string),
		Key:                 key,
		Nonce:               nonce,
	}

	f, fi, err := files.OpenPath(source)
	if err != nil {
		err = stacktrace.Propagate(err, "could not open '%s'", source)
		return nil, err
	}
	defer f.Close()
	if !fi.IsDir() {
		parent := filepath.Dir(source)
		r.Targets[source] = primitives.PathJoin(parent, filepath.Base(source)+".enc")
	} else {
		files, err := files.ReadDirFiles(source, regex)
		if err != nil {
			err = stacktrace.Propagate(err, "could search '%s' for '%s' pattern", source, regex)
			return nil, err
		}
		for _, v := range files {
			v = primitives.PathJoin(source, v)
			parent := filepath.Dir(v)
			value := primitives.PathJoin(parent, filepath.Base(v)+".enc")
			r.Targets[v] = value
			r.logger.Trace("new-encrypt-request: %s=>%s", v, value)
		}
	}
	return r, nil
}

// Sanitize ...
func (r *EncryptRequest) Sanitize() error {
	var err error
	if r.logger == nil {
		err = stacktrace.NewError("logger was nil")
		return err
	}
	if len(r.Targets) == 0 {
		err = stacktrace.NewError("input path is empty")
		return err
	}
	// appending destination root path if exists
	if len(r.DestinationRootPath) != 0 {
		r.DestinationRootPath, err = filepath.Abs(r.DestinationRootPath)
		if err != nil {
			err = stacktrace.Propagate(err, "could not get aboslute path for destination root path of '%v'", r.DestinationRootPath)
			return err
		}

		for k, v := range r.Targets {
			delete(r.Targets, k)
			value := primitives.PathJoin(r.DestinationRootPath, v)
			r.Targets[k] = value
			r.logger.Trace("encrypt-request-sanitize: %s=>%s", k, value)
		}
	}
	return nil
}

// EncryptResponse ...
type EncryptResponse struct {
	EncryptedArtifacts map[string]Hash       `json:"encrypted_artifacts,omitempty" mapstructure:"encrypted_artifacts,omitempty"`
	RandomNonce        string                `json:"random_nonce,omitempty" mapstructure:"random_nonce,omitempty"`
	UUID               string                `json:"uuid,omitempty" mapstructure:"uuid,omitempty"`
	logger             *logger.WrappedLogger `json:"-" `
}

// Response ...
func (r *EncryptRequest) Response() *EncryptResponse {

	return &EncryptResponse{
		UUID:               r.UUID,
		logger:             r.logger,
		EncryptedArtifacts: make(map[string]Hash),
		RandomNonce:        hex.EncodeToString(r.Nonce[:]),
	}
}

// Sanitize ...
func (r *EncryptResponse) Sanitize() error {
	var err error
	if r.logger == nil {
		err = stacktrace.NewError("logger was nil")
		return err
	}
	if len(r.RandomNonce) == 0 {
		err = stacktrace.NewError("random nonce for encrypt response is empty")
		return err
	}
	for k, v := range r.EncryptedArtifacts {
		if len(k) == 0 {
			err = stacktrace.NewError("output path for encrypt response is empty")
			return err
		}
		err = v.Sanitize()
		if err != nil {
			err = stacktrace.Propagate(err, "could not Sanitize Hash")
			return err
		}
	}
	return nil
}
func (r *EncryptResponse) String() []string {
	result := []string{"- UUID:" + r.UUID, "- RandomNonce:" + r.RandomNonce, "- encrypted artifacts:"}
	for k, v := range r.EncryptedArtifacts {
		result = append(result, fmt.Sprintf("%s=>{md5: '%s' | sha256: '%s'}", k, v.Md5, v.Sha256))
	}
	return result
}
