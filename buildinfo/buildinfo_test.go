package buildinfo

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestResolve_Defaults(t *testing.T) {
	// Reset package-level vars to simulate bare "go build" (no ldflags).
	Version = ""
	Revision = ""
	BuildID = ""
	BuildTime = ""
	// Reset singleton so resolve() runs fresh.
	once = syncOnce()

	info := Get()

	if info.Version != "dev" {
		t.Errorf("expected Version='dev', got %q", info.Version)
	}
	if info.BuildID != "unknown" {
		t.Errorf("expected BuildID='unknown', got %q", info.BuildID)
	}
	if info.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}
}

func TestResolve_WithLdflags(t *testing.T) {
	Version = "1.0.2-alpha"
	Revision = "a3f7b2c1e9d4"
	BuildID = "f7a2"
	BuildTime = "2026-04-16T10:30:00Z"
	once = syncOnce()

	info := Get()

	if info.Version != "1.0.2-alpha" {
		t.Errorf("expected Version='1.0.2-alpha', got %q", info.Version)
	}
	if info.Revision != "a3f7b2c1e9d4" {
		t.Errorf("expected Revision='a3f7b2c1e9d4', got %q", info.Revision)
	}
	if info.Dirty {
		t.Error("expected Dirty=false for clean revision")
	}
	if info.BuildID != "f7a2" {
		t.Errorf("expected BuildID='f7a2', got %q", info.BuildID)
	}
	if info.BuildTime != "2026-04-16T10:30:00Z" {
		t.Errorf("expected BuildTime='2026-04-16T10:30:00Z', got %q", info.BuildTime)
	}
}

func TestResolve_DirtyRevision(t *testing.T) {
	Version = "dev"
	Revision = "a3f7b2c1e9d4-dirty"
	BuildID = "e3b1"
	BuildTime = "2026-04-16T10:50:00Z"
	once = syncOnce()

	info := Get()

	if !info.Dirty {
		t.Error("expected Dirty=true for revision with -dirty suffix")
	}
	if info.Revision != "a3f7b2c1e9d4-dirty" {
		t.Errorf("expected Revision='a3f7b2c1e9d4-dirty', got %q", info.Revision)
	}
}

func TestString_WithBuildID(t *testing.T) {
	Version = "1.0.2-alpha"
	Revision = "a3f7b2c1e9d4"
	BuildID = "f7a2"
	BuildTime = "2026-04-16T10:30:00Z"
	once = syncOnce()

	s := Get().String()
	// Expected: "1.0.2-alpha+a3f7b2c1e9d4.f7a2 (built 2026-04-16T10:30:00Z, go1.x.y)"
	if !strings.Contains(s, "1.0.2-alpha+a3f7b2c1e9d4.f7a2") {
		t.Errorf("String() missing version+revision.buildid: %q", s)
	}
	if !strings.Contains(s, "built 2026-04-16T10:30:00Z") {
		t.Errorf("String() missing build time: %q", s)
	}
}

func TestString_WithoutBuildID(t *testing.T) {
	Version = "dev"
	Revision = "a3f7b2c1e9d4-dirty"
	BuildID = ""
	BuildTime = ""
	once = syncOnce()

	s := Get().String()
	// Expected: "dev+a3f7b2c1e9d4-dirty (built unknown, go1.x.y)"
	if strings.Contains(s, ".unknown") {
		t.Errorf("String() should omit .buildid when unknown: %q", s)
	}
	if !strings.Contains(s, "dev+a3f7b2c1e9d4-dirty") {
		t.Errorf("String() missing version+revision: %q", s)
	}
}

func TestJSON(t *testing.T) {
	Version = "1.0.2-alpha"
	Revision = "a3f7b2c1e9d4"
	BuildID = "f7a2"
	BuildTime = "2026-04-16T10:30:00Z"
	once = syncOnce()

	data := Get().JSON()

	var parsed Info
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON() produced invalid JSON: %v", err)
	}
	if parsed.Version != "1.0.2-alpha" {
		t.Errorf("JSON version mismatch: %q", parsed.Version)
	}
	if parsed.BuildID != "f7a2" {
		t.Errorf("JSON build_id mismatch: %q", parsed.BuildID)
	}
	if parsed.Dirty {
		t.Error("JSON dirty should be false")
	}
}

// syncOnce returns a fresh sync.Once to reset the singleton for testing.
func syncOnce() sync.Once {
	return sync.Once{}
}
