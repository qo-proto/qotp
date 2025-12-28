package qotp

import (
	"log/slog"
	"os"
	"strings"

	"github.com/MatusOllah/slogcolor"
	"github.com/fatih/color"
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
	colorEnv := strings.ToLower(os.Getenv("NO_COLOR"))
	color.NoColor = colorEnv != ""
	slog.SetDefault(logger)
}
