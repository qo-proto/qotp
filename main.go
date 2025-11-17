package qotp

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/MatusOllah/slogcolor"
	"github.com/fatih/color"
)

const (
	rcvBufferCapacity = 16 * 1024 * 1024 // 16MB
	sndBufferCapacity = 16 * 1024 * 1024 // 16MB
	secondNano        = 1_000_000_000
	msNano            = 1_000_000
)

func init() {
	levelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))
	var slogLevel slog.Level
	switch levelStr {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info", "":
		slogLevel = slog.LevelInfo
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	setupLogger(slogLevel)
}

func setupLogger(level slog.Level) {
	logger := slog.New(slogcolor.NewHandler(os.Stderr, &slogcolor.Options{
		Level:         level,
		TimeFormat:    "15:04:05.000",
		SrcFileMode:   slogcolor.ShortFile,
		SrcFileLength: 16,
		MsgPrefix:     color.HiWhiteString("|"),
		MsgColor:      color.New(color.FgHiWhite),
		MsgLength:     24,
	}))
	color.NoColor = false
	slog.SetDefault(logger)
}

func gId() slog.Attr {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	idField := bytes.Fields(buf)[1]
	var id int64
	fmt.Sscanf(string(idField), "%d", &id)
	return slog.String("gid", fmt.Sprintf("0x%02x", id))
}
