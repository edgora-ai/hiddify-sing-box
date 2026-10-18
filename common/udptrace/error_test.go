package udptrace

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

type noTextError struct {
	cause error
}

func (e noTextError) Error() string {
	panic("diagnostic inspected error text")
}

func (e noTextError) Unwrap() error {
	return e.cause
}

type untrustedTimeout struct{}

func (untrustedTimeout) Error() string {
	panic("diagnostic inspected untrusted error text")
}

func (untrustedTimeout) Timeout() bool {
	panic("diagnostic invoked an unlisted timeout implementation")
}

func (untrustedTimeout) Temporary() bool {
	panic("diagnostic invoked an unlisted temporary implementation")
}

func TestUDPTraceErrorClassificationWhitelist(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"success", nil, ErrorNone},
		{"eof", io.EOF, ErrorEOF},
		{"unexpected eof", io.ErrUnexpectedEOF, ErrorUnexpectedEOF},
		{"canceled", context.Canceled, ErrorCanceled},
		{"context deadline", context.DeadlineExceeded, ErrorDeadline},
		{"os deadline", os.ErrDeadlineExceeded, ErrorDeadline},
		{"network closed", net.ErrClosed, ErrorClosed},
		{"file closed", os.ErrClosed, ErrorClosed},
		{"syscall timeout", syscall.ETIMEDOUT, ErrorTimeout},
		{"dns timeout", &net.DNSError{Err: "private-dns-message-sentinel", Name: "private-name-sentinel", IsTimeout: true}, ErrorTimeout},
		{"dns other", &net.DNSError{Err: "timeout", Name: "private-name-sentinel"}, ErrorOther},
		{"network wrapped deadline", &net.OpError{Op: "private-op-sentinel", Net: "udp", Err: os.ErrDeadlineExceeded}, ErrorDeadline},
		{"syscall wrapped timeout", &os.SyscallError{Syscall: "private-syscall-sentinel", Err: syscall.ETIMEDOUT}, ErrorTimeout},
		{"connection reset", syscall.ECONNRESET, ErrorOther},
		{"short write", io.ErrShortWrite, ErrorOther},
		{"text only timeout", errors.New("i/o timeout"), ErrorOther},
		{"text only eof", errors.New("EOF"), ErrorOther},
		{"private error", errors.New("private-error-message-sentinel"), ErrorOther},
		{"unlisted timeout type", untrustedTimeout{}, ErrorOther},
		{"no text", noTextError{}, ErrorOther},
		{"joined", errors.Join(noTextError{io.EOF}, context.Canceled), ErrorCanceled},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyError(test.err); got != test.want {
				t.Fatalf("classify %T = %q; want %q", test.err, got, test.want)
			}
			if test.err != nil {
				if got := ClassifyError(noTextError{test.err}); got != test.want {
					t.Fatalf("classify wrapped %T = %q; want %q", test.err, got, test.want)
				}
			}
		})
	}
}
