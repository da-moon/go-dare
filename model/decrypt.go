package model

import (
	"fmt"
	"path/filepath"
	"strings"

	files "github.com/da-moon/go-files"
	logger "github.com/da-moon/go-logger"
	primitives "github.com/da-moon/go-primitives"
	stacktrace "github.com/palantir/stacktrace"
)

// DecryptRequest ...
type DecryptRequest struct {
	Targets             map[string]string     `json:"targets,omitempty" mapstructure:"targets,omitempty"`
	UUID                string                `json:"uuid,omitempty" mapstructure:"uuid,omitempty"`
	DestinationRootPath string                `json:"destination_root_path,omitempty" mapstructure:"destination_root_path,omitempty"`
	logger              *logger.WrappedLogger `json:"-"`
	Key                 [32]byte
	Nonce               [24]byte
}

// NewDecryptRequest adds a target path to Decrypt
func (k *Key) NewDecryptRequest(source, destinationRoot string) (*DecryptRequest, error) {
	var err error
	source, err = filepath.Abs(source)
	if err != nil {
		err = stacktrace.Propagate(err, "could not get aboslute path for source path of '%v'", source)
		return nil, err
	}
	key, err := k.GetEncryptionKey()
	if err != nil {
		err = stacktrace.Propagate(err, "could not extract Encryption key")
		return nil, err
	}
	nonce, err := k.GetNonce()
	if err != nil {
		err = stacktrace.Propagate(err, "could not extract nonce")
		return nil, err
	}
	r := &DecryptRequest{
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
		r.logger.Trace("new-decrypt-request origin-base : %s=>%s", source, filepath.Base(source))
		value := primitives.PathJoin(parent, strings.TrimSuffix(filepath.Base(source), ".enc"))
		r.Targets[source] = value
		r.logger.Trace("new-decrypt-request: %s=>%s", source, value)
	} else {
		files, err := files.ReadDirFiles(source, "*.enc")
		if err != nil {
			err = stacktrace.Propagate(err, "could search '%s' for '*.enc' pattern", source)
			return nil, err
		}
		for _, v := range files {
			v = primitives.PathJoin(source, v)
			parent := filepath.Dir(v)
			value := primitives.PathJoin(parent, strings.TrimSuffix(filepath.Base(v), ".enc"))
			r.Targets[v] = value
			r.logger.Trace("new-decrypt-request: %s=>%s", v, value)
		}
	}
	return r, nil
}

// Sanitize ...
func (r *DecryptRequest) Sanitize() error {
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
			r.logger.Trace("decrypt-request-sanitize: %s=>%s", k, value)
		}
	}
	return nil
}

// DecryptResponse ...
type DecryptResponse struct {
	DecryptedArtifacts map[string]Hash       `json:"decrypted_artifacts,omitempty" mapstructure:"decrypted_artifacts,omitempty"`
	UUID               string                `json:"uuid,omitempty" mapstructure:"uuid,omitempty"`
	logger             *logger.WrappedLogger `json:"-" mapstructure:"-"`
}

// Response ...
func (r *DecryptRequest) Response() *DecryptResponse {
	return &DecryptResponse{
		UUID:               r.UUID,
		logger:             r.logger,
		DecryptedArtifacts: make(map[string]Hash),
	}
}

// Sanitize ...
func (r *DecryptResponse) Sanitize() error {
	var err error
	if r.logger == nil {
		err = stacktrace.NewError("logger was nil")
		return err
	}
	for k, v := range r.DecryptedArtifacts {
		if len(k) == 0 {
			err = stacktrace.NewError("output path for decrypt response is empty")
			return err
		}
		err = v.Sanitize()
		if err != nil {
			err = stacktrace.Propagate(err, "could not sanitize Hash")
			return err
		}
	}
	return nil
}

func (r *DecryptResponse) String() []string {
	result := []string{"- UUID:" + r.UUID, "- decrypted artifacts:"}
	for k, v := range r.DecryptedArtifacts {
		result = append(result, fmt.Sprintf("%s=>{md5: '%s' | sha256: '%s'}", k, v.Md5, v.Sha256))
	}
	return result
}
