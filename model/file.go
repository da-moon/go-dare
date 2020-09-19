package model

// import (
// 	logger "github.com/da-moon/go-logger"
// 	stacktrace "github.com/palantir/stacktrace"
// )

// // File ...
// type File struct {
// 	Source      string                `json:"source,omitempty" mapstructure:"source,omitempty"`
// 	Destination string                `json:"destination,omitempty" mapstructure:"destination,omitempty"`
// 	UUID        string                `json:"uuid,omitempty" mapstructure:"uuid,omitempty"`
// 	logger      *logger.WrappedLogger `json:"-" `
// }

// // Sanitize ...
// func (r *File) Sanitize(l *logger.WrappedLogger, uuid string) error {
// 	var err error
// 	if l == nil {
// 		err = stacktrace.NewError("file: logger was nil")
// 		return err
// 	}
// 	r.UUID = uuid
// 	r.logger = l
// 	if len(r.Source) == 0 {
// 		err = stacktrace.NewError("file : input path is empty")
// 		return err
// 	}
// 	// if len(r.Destination) == 0 {
// 	// }
// 	r.logger.Trace("[%s] file => File.Source '%s'", r.UUID, r.Source)
// 	r.logger.Trace("[%s] file => File.Destination '%s'", r.UUID, r.Destination)
// 	return nil
// }
