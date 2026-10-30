package loader

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests check what a spec can make Procyon read. They call Load,
// which procyon lint and procyon test both go through.

// A symlink inside the spec's directory must not become a way out of it.
func TestRefThroughSymlinkCannotLeaveTheSpecDirectory(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(secret, []byte("get:\n  responses: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(dir, "orders.yaml")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	spec := filepath.Join(dir, "api.yaml")
	body := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"./orders.yaml\"\n"
	if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(spec, Options{})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Load = %v, want an error refusing the symlink", err)
	}
}

// The attack found in review: an absolute $ref through a committed symlink
// and "..", where the path checked and the path read used to differ.
func TestRefCannotEscapeWithAbsolutePathThroughSymlink(t *testing.T) {
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	stolen := "get:\n  description: STOLEN\n  responses:\n    \"200\":\n      description: OK\n"
	if err := os.WriteFile(filepath.Join(outside, "secret.yaml"), []byte(stolen), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "sub"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	// A harmless decoy where the cleaned path points, so a check on the
	// cleaned path passes while a read of the raw path follows the link.
	decoy := "get:\n  responses:\n    \"200\":\n      description: OK\n"
	if err := os.WriteFile(filepath.Join(dir, "secret.yaml"), []byte(decoy), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := filepath.ToSlash(filepath.Join(dir, "link")) + "/../secret.yaml"
	spec := filepath.Join(dir, "api.yaml")
	body := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"" + ref + "\"\n"
	if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(spec, Options{})
	if err != nil {
		return // refused: nothing was read
	}
	for _, lines := range loaded.Sources() {
		if strings.Contains(strings.Join(lines, "\n"), "STOLEN") {
			t.Fatal("Procyon read a file outside the spec's directory")
		}
	}
	// Reading the decoy inside the directory is fine; the stolen file is not.
	t.Logf("read %d files, none of them the stolen one", len(loaded.Sources()))
}

// A $ref to an absolute path outside the allowed directories is refused
// without touching the file system: same message whether the file exists or
// not, so a spec cannot probe the machine running Procyon.
var quotedRef = regexp.MustCompile(`\$ref "[^"]*"`)

func TestRefOutsideGivesTheSameErrorWhetherOrNotTheFileExists(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "exists.yaml")
	if err := os.WriteFile(existing, []byte("get: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	var messages []string
	for _, target := range []string{existing, missing} {
		dir := t.TempDir()
		spec := filepath.Join(dir, "api.yaml")
		body := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"" + filepath.ToSlash(target) + "\"\n"
		if err := os.WriteFile(spec, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(spec, Options{})
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("Load = %v, want an error saying the $ref points outside", err)
		}
		// The $ref is quoted as the system writes it (c:\\Users\\… on
		// Windows): compare everything but the path itself.
		msg := quotedRef.ReplaceAllString(err.Error(), `$$ref "TARGET"`)
		messages = append(messages, strings.ReplaceAll(msg, dir, "DIR"))
	}
	for i := range messages {
		messages[i] = messages[i][strings.Index(messages[i], "$ref"):]
	}
	if messages[0] != messages[1] {
		t.Errorf("messages differ, revealing whether the file exists:\n %s\n %s", messages[0], messages[1])
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The spec itself must be a regular file: a symlink to a device or to a file
// outside the repository is refused.
func TestSpecMustBeARegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere.yaml")
	writeFile(t, target, "openapi: 3.0.3\ninfo:\n  title: x\n  version: \"1\"\npaths: {}\n")
	link := filepath.Join(dir, "api.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	_, err := Load(link, Options{})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load = %v, want an error refusing a symlinked spec", err)
	}
}

// A spec reached through a directory symlink that leads out of the working
// directory is refused, like a symlinked spec file.
func TestSpecBehindADirectorySymlinkLeavingTheWorkingDirectoryIsRefused(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "openapi.yaml"), "openapi: 3.0.3\ninfo:\n  title: x\n  version: \"1\"\npaths: {}\n")
	work := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(work, "api")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	t.Chdir(work)
	_, err := Load(filepath.Join("api", "openapi.yaml"), Options{})
	if err == nil || !strings.Contains(err.Error(), "outside the working directory") {
		t.Fatalf("Load = %v, want an error refusing a spec reached through a link leading out", err)
	}
}
