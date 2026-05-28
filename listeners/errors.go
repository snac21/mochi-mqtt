// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt

package listeners

import (
	"errors"
	"io"
	"net"
	"syscall"

	"log/slog"
)

func isExpectedCloseError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

func logEstablishError(log *slog.Logger, err error) {
	if err == nil || isExpectedCloseError(err) {
		return
	}

	log.Warn("", "error", err)
}
