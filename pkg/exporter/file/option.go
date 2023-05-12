package file

import (
	"fmt"
	"io"
	"os"
)

type options struct {
	Writer io.Writer
	Pretty bool
}

var defaultOptions = options{
	Writer: os.Stdout,
	Pretty: false,
}

type Option func(o *options) error

func newOptions(opts ...Option) (*options, error) {
	options := defaultOptions
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	return &options, nil
}

func WithWriter(writer io.Writer) Option {
	return func(o *options) error {
		o.Writer = writer
		return nil
	}
}

func WithPretty() Option {
	return func(o *options) error {
		o.Pretty = true
		return nil
	}
}
