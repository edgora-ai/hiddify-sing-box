package udptrace

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
)

func ClassifyError(err error) ErrorKind {
	switch {
	case err == nil:
		return ErrorNone
	case errors.Is(err, context.Canceled):
		return ErrorCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return ErrorDeadline
	case errors.Is(err, net.ErrClosed), errors.Is(err, os.ErrClosed):
		return ErrorClosed
	case errors.Is(err, io.ErrUnexpectedEOF):
		return ErrorUnexpectedEOF
	case errors.Is(err, io.EOF):
		return ErrorEOF
	case errors.Is(err, syscall.ETIMEDOUT):
		return ErrorTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError != nil && dnsError.IsTimeout {
		return ErrorTimeout
	}
	return ErrorOther
}
