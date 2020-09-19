package dare

import (
	"io"
	"os"
	"path/filepath"

	config "github.com/da-moon/go-dare/internal/config"
	decryptor "github.com/da-moon/go-dare/internal/decryptor"
	model "github.com/da-moon/go-dare/model"
	files "github.com/da-moon/go-files"
	stream "github.com/da-moon/go-stream"
	stacktrace "github.com/palantir/stacktrace"
)

// DecryptWithWriter ...
func DecryptWithWriter(
	dstwriter io.Writer,
	srcReader io.Reader,
	key [32]byte,
	nonce [24]byte,
) error {
	decWriter := decryptor.NewWriter(dstwriter, nonce, &key)
	for {
		buffer := make([]byte, config.DefaultChunkSize+config.DefaultOverhead)
		bytesRead, err := srcReader.Read(buffer)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		_, err = decWriter.Write(buffer[:bytesRead])
		if err != nil {
			return err
		}
	}
	return nil
}

// DecryptFile ...
func DecryptFile(r *model.DecryptRequest) (*model.DecryptResponse, error) {
	var err error
	if r == nil {
		err = stacktrace.NewError("nil request")
		return nil, err
	}
	err = r.Sanitize()
	if err != nil {
		err = stacktrace.Propagate(err, "could not sanitize request")
		return nil, err
	}
	result := r.Response()
	for k, v := range r.Targets {
		srcFile, _, err := files.SafeOpenPath(k)
		if err != nil {
			err = stacktrace.Propagate(err, "could not decrypt '%s'", k)
			return nil, err
		}
		defer srcFile.Close()

		os.Remove(v)
		files.MkdirAll(filepath.Dir(v))
		destinationFile, err := os.Create(v)
		if err != nil {
			err = stacktrace.NewError("could not successfully create a new empty file for %s", v)
			return nil, err
		}
		defer destinationFile.Close()
		dstWriter, err := stream.NewHashWriter(
			destinationFile,
			stream.WithMD5(),
			stream.WithSHA256(),
		)
		if err != nil {
			err = stacktrace.Propagate(err, "Could create a new hashwriter for '%s'  ", k)
			return nil, err
		}
		defer stream.ShutdownMD5Hasher()
		err = DecryptWithWriter(dstWriter, srcFile, r.Key, r.Nonce)
		if err != nil {
			err = stacktrace.Propagate(err, "Could not decrypt file at '%s' and store it in '%s' ", k, v)
			return nil, err
		}
		md5Hex, err := dstWriter.HexString(stream.MD5)
		if err != nil {
			err = stacktrace.Propagate(err, "could not calculate hex encoded md5 hash of '%s' ", v)
			return nil, err
		}
		sha256Hex, err := dstWriter.HexString(stream.SHA256)
		if err != nil {
			err = stacktrace.Propagate(err, "could not calculate hex encoded sha256 hash of '%s' ", v)
			return nil, err
		}
		result.DecryptedArtifacts[v] = model.Hash{
			Md5:    md5Hex,
			Sha256: sha256Hex,
		}
	}
	err = result.Sanitize()
	if err != nil {
		err = stacktrace.Propagate(err, "could not Sanitize Encrypt Response")
		return nil, err
	}
	return result, nil
}
