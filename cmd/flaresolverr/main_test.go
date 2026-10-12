package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		in   string
		want zerolog.Level
	}{
		{"trace", zerolog.TraceLevel},
		{"debug", zerolog.DebugLevel},
		{"DEBUG", zerolog.DebugLevel},
		{"Debug", zerolog.DebugLevel},
		{" debug ", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"WARNING", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
		{"fatal", zerolog.FatalLevel},
		{"FATAL", zerolog.FatalLevel},
		{"", zerolog.InfoLevel},
		{"verbose", zerolog.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := parseLogLevel(tt.in); got != tt.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestSetupLogging_ReturnsFileWriter verifies the file sink is handed back (so
// the dashboard can keep feeding it) and receives log lines.
func TestSetupLogging_ReturnsFileWriter(t *testing.T) {
	origLogger, origLevel := log.Logger, zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = origLogger
		zerolog.SetGlobalLevel(origLevel)
	})

	// setupLogging prints to stdout; keep the test output clean
	origStdout := os.Stdout
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	os.Stdout = devNull
	t.Cleanup(func() {
		os.Stdout = origStdout
		devNull.Close()
	})

	t.Run("no log file", func(t *testing.T) {
		if w := setupLogging("info", ""); w != nil {
			t.Errorf("setupLogging without LOG_FILE returned a file writer")
		}
	})

	t.Run("with log file and upper-case level", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "flaresolverr.log")
		w := setupLogging("DEBUG", path)
		if w == nil {
			t.Fatal("setupLogging returned no file writer")
		}
		if closer, ok := w.(io.Closer); ok {
			t.Cleanup(func() { closer.Close() })
		}
		if got := zerolog.GlobalLevel(); got != zerolog.DebugLevel {
			t.Errorf("global level = %v, want debug for LOG_LEVEL=DEBUG", got)
		}

		log.Debug().Msg("line-for-the-file")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read log file: %v", err)
		}
		if !bytes.Contains(data, []byte("line-for-the-file")) {
			t.Errorf("log file does not contain the logged line: %q", data)
		}
	})
}
