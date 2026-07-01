package ping

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantLines int
		wantErr   bool
	}{
		{
			name:      "default count is one",
			args:      []string{},
			wantLines: 1,
			wantErr:   false,
		},
		{
			name:      "count flag repeats output",
			args:      []string{"--count", "3"},
			wantLines: 3,
			wantErr:   false,
		},
		{
			name:      "count zero returns error",
			args:      []string{"--count", "0"},
			wantLines: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Command()
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if tt.wantErr {
				if err == nil {
					t.Fatal("Execute() got nil error, want non-nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Execute() returned unexpected error: %v", err)
			}

			gotLines := strings.Count(buf.String(), "pong")
			if gotLines != tt.wantLines {
				t.Errorf("pong count = %d, want %d (output: %q)", gotLines, tt.wantLines, buf.String())
			}
		})
	}
}
