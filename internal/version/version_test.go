package version

import (
	"strings"
	"testing"
)

func TestVersion_DefaultValue(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want %q", Version, "dev")
	}
}

func TestString_ContainsVersion(t *testing.T) {
	got := String()
	if !strings.Contains(got, Version) {
		t.Errorf("String() = %q, want it to contain Version %q", got, Version)
	}
}
