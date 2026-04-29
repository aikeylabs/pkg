package aikeycompat

import (
	"os"
	"path/filepath"
	"testing"
)

// EnforceOwnerOnly must be cleanly idempotent — vault init / WAL writer
// init etc. all call it on every startup, so a non-idempotent
// implementation would either fail the second run or silently double up
// ACEs (Windows). This test is platform-agnostic because the contract
// is: "calling twice returns nil twice".
func TestEnforceOwnerOnlyIdempotent(t *testing.T) {
	dir := t.TempDir()
	for round := 1; round <= 3; round++ {
		if err := EnforceOwnerOnly(dir); err != nil {
			t.Fatalf("round %d: EnforceOwnerOnly failed: %v", round, err)
		}
	}
}

// Non-existent paths must be a no-op, not an error. Caller's
// MkdirAll/WriteFile is the source of truth for "does this exist";
// EnforceOwnerOnly is a best-effort hardening pass that should never
// turn a non-existence into a startup failure.
func TestEnforceOwnerOnlyNonexistentPathIsNoop(t *testing.T) {
	dir := t.TempDir()
	phantom := filepath.Join(dir, "no-such-subdir")
	if _, err := os.Stat(phantom); !os.IsNotExist(err) {
		t.Fatal("test invariant: phantom path must not exist")
	}
	if err := EnforceOwnerOnly(phantom); err != nil {
		t.Errorf("expected nil for non-existent path; got %v", err)
	}
}

// Real file inside a real dir — both should succeed.
func TestEnforceOwnerOnlyOnFileAndDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "vault.db")
	if err := os.WriteFile(file, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := EnforceOwnerOnly(dir); err != nil {
		t.Errorf("EnforceOwnerOnly(dir): %v", err)
	}
	if err := EnforceOwnerOnly(file); err != nil {
		t.Errorf("EnforceOwnerOnly(file): %v", err)
	}
}
