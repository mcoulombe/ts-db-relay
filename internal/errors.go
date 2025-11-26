package internal

import "fmt"

type Origin string

const (
	OriginClient   Origin = "client"
	OriginServer   Origin = "server"
	OriginExternal Origin = "external"
)

type RelayError struct {
	// Origin indicates the best guess as to who is the culprit of the error
	Origin Origin `json:"origin"`
	// Code is a machine-readable error code. Machine codes should never be changed.
	Code string `json:"code"`
	// Message is a human-readable error message. This message may change over time.
	Message string `json:"message"`
	// Underlying is the underlying error that caused this error, if any.
	// It is omitted from JSON serialization to avoid exposing sensitive information outside internal logs.
	Underlying error `json:"-"`
}

func NewError(origin Origin, code, message string, underlying error) *RelayError {
	return &RelayError{origin, code, message, underlying}
}

func (e *RelayError) Error() string {
	return e.Message
}

func (e *RelayError) Internal() string {
	if e.Underlying != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Underlying)
	}
	return e.Message
}

func (e *RelayError) Unwrap() error {
	return e.Underlying
}
