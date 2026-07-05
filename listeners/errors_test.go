// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt

package listeners

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsExpectedCloseError(t *testing.T) {
	require.False(t, isExpectedCloseError(nil))
	require.True(t, isExpectedCloseError(io.EOF))
	require.True(t, isExpectedCloseError(io.ErrClosedPipe))
	require.True(t, isExpectedCloseError(net.ErrClosed))
	require.True(t, isExpectedCloseError(errors.Join(errors.New("wrapped"), syscall.ECONNRESET)))
	require.False(t, isExpectedCloseError(errors.New("malformed packet")))
}

func TestLogEstablishErrorSuppressesExpectedCloseErrors(t *testing.T) {
	for _, err := range []error{
		nil,
		io.EOF,
		io.ErrClosedPipe,
		net.ErrClosed,
		syscall.ECONNRESET,
		syscall.EPIPE,
		errors.Join(errors.New("wrapped"), syscall.ECONNRESET),
	} {
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, nil))

		logEstablishError(log, err)

		require.Empty(t, buf.String())
	}
}

func TestLogEstablishErrorWarnsUnexpectedErrors(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	logEstablishError(log, errors.New("malformed packet"))

	require.Contains(t, buf.String(), "malformed packet")
	require.Contains(t, buf.String(), "level=WARN")
}

func TestListenerEstablishPathsUseSharedErrorLogger(t *testing.T) {
	for _, file := range []string{"tcp.go", "net.go", "unixsock.go", "websocket.go"} {
		src, err := os.ReadFile(file)
		require.NoError(t, err)
		require.Contains(t, string(src), "logEstablishError(", file)
	}
}
