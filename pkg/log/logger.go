package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"
	"os"
)

var (
	Logger *zap.SugaredLogger
	Debug  bool
)

func init() {
	Logger, _ = NewLogger(false) // nolint: errcheck
}

// InitLogger initialize the logger variable
func InitLogger(debug bool) (err error) {
	Debug = debug
	Logger, err = NewLogger(debug)
	if err != nil {
		return xerrors.Errorf("failed to initialize the logger: %w", err)
	}

	return nil

}

// NewLogger returns an instance of logger
func NewLogger(debug bool) (*zap.SugaredLogger, error) {
	errorLevel := zap.LevelEnablerFunc(func(level zapcore.Level) bool {
		return level >= zapcore.ErrorLevel
	})
	logLevel := zap.LevelEnablerFunc(func(level zapcore.Level) bool {
		if debug {
			return level < zapcore.ErrorLevel
		}
		// Do not enable debug
		return zapcore.DebugLevel < level && level < zapcore.ErrorLevel
	})

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "Time",
		LevelKey:       "Level",
		NameKey:        "Name",
		CallerKey:      "Caller",
		MessageKey:     "Msg",
		StacktraceKey:  "St",
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	// High-priority output goes to standard error
	// Low-priority output goes to standard out
	consoleLogs := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, errorLevel),
		zapcore.NewCore(consoleEncoder, consoleLogs, logLevel),
	)

	opts := []zap.Option{zap.ErrorOutput(zapcore.Lock(os.Stderr))}
	if debug {
		opts = append(opts, zap.Development())
	}
	logger := zap.New(core, opts...)

	return logger.Sugar(), nil
}

// Fatal for logging fatal errors
func Fatal(err error) {
	if Debug {
		Logger.Fatalf("%+v", err)
	}
	Logger.Fatal(err)
}
