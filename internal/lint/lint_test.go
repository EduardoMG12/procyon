package lint_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/lint"
)

func TestRunAcceptsValidSpecs(t *testing.T) {
	specs := []string{
		"valid-3.0.yaml",
		"valid-3.1.yaml",
		"valid-3.0.json",
		"valid-3.1.json",
		"valid-wrong-example.yaml", // examples and defaults are not security: never block a lint
		"valid-wrong-default.yaml",
		"valid-conflicting-paths.yaml", // /users/{id} and /users/{name}: invalid OpenAPI, not a security problem
		"swagger-2.0.yaml",
	}
	for _, name := range specs {
		t.Run(name, func(t *testing.T) {
			if _, err := lint.Run(spec(name), lint.Options{}); err != nil {
				t.Fatalf("Run(%s) returned error: %v", name, err)
			}
		})
	}
}

func spec(name string) string {
	return "../../testdata/specs/" + name
}

func TestRunRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		file string
		want []string // substrings the one-line error must contain
	}{
		{"missing file", "does-not-exist.yaml", []string{"does-not-exist.yaml"}},
		{"invalid YAML", "invalid-yaml.yaml", []string{"invalid-yaml.yaml:7:10:"}},
		{"invalid JSON", "invalid-json.json", []string{"invalid-json.json:4:23:"}},
		{"spec without info", "invalid-spec-no-info.yaml", []string{"invalid-spec-no-info.yaml", "info"}},
		{"public operation without a reason", "public-empty-reason.yaml", []string{"public-empty-reason.yaml:7:5:", "GET /health", "x-procyon-public", "reason"}},
		{"public operation marked with a boolean", "public-not-a-string.yaml", []string{"public-not-a-string.yaml:7:5:", "GET /health", "x-procyon-public", "reason"}},
		{"remote $ref", "ref-remote.yaml", []string{"ref-remote.yaml", "https://example.com/orders.yaml", "never fetches"}},
		{"missing local $ref", "ref-missing.yaml", []string{"ref-missing.yaml", "missing.yaml"}},
		{"$ref escaping the working directory", "ref-escapes.yaml", []string{"ref-escapes.yaml", "outside"}},
		{"undefined scheme does not hide another error", "invalid-spec-and-undefined-scheme.yaml", []string{"invalid-spec-and-undefined-scheme.yaml", "info"}},
		// PRC002 does not look into webhooks or callbacks, so an undefined
		// scheme there must still stop the run instead of passing silently.
		{"undefined scheme in a webhook", "invalid-undefined-scheme-in-webhook.yaml", []string{"undefined security scheme", "missing"}},
		{"undefined scheme in a callback", "invalid-undefined-scheme-in-callback.yaml", []string{"undefined security scheme", "missing"}},
		// A typo in an ignore must never silently ignore something.
		{"ignore without a reason", "ignore-no-reason.yaml", []string{"ignore-no-reason.yaml:8:7:", "GET /health", "reason"}},
		{"ignore of an unknown rule", "ignore-unknown-rule.yaml", []string{"ignore-unknown-rule.yaml:8:7:", "PRC01"}},
		{"ignore with a malformed date", "ignore-bad-date.yaml", []string{"ignore-bad-date.yaml:8:7:", "expires", "tomorrow"}},
		{"ignore that is not a list", "ignore-not-a-list.yaml", []string{"ignore-not-a-list.yaml:8:7:", "list"}},
		{"Swagger 2.0 with a null path item", "swagger-2.0-null.yaml", []string{"swagger-2.0-null.yaml:6:3:", "/u"}},
		{"Swagger 2.0 path item $ref", "swagger-2.0-pathref.yaml", []string{"swagger-2.0-pathref.yaml", "/users", "$ref"}},
		{"Swagger 2.0 YAML alias bomb of long strings", "swagger-2.0-string-bomb.yaml", []string{"swagger-2.0-string-bomb.yaml", "alias"}},
		{"Swagger 2.0 with a null default response", "swagger-2.0-null-default.yaml", []string{"swagger-2.0-null-default.yaml:9:9:", "default"}},
		{"Swagger 2.0 YAML alias bomb", "swagger-2.0-alias-bomb.yaml", []string{"swagger-2.0-alias-bomb.yaml", "alias"}},
		{"Swagger 2.0 split across files", "swagger-2.0-split.yaml", []string{"swagger-2.0-split.yaml", "./definitions.yaml#/User", "one file"}},
		{"public marker error keeps the path as written", "dir with space/public-empty-reason.yaml", []string{"dir with space/public-empty-reason.yaml:7:5:"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := lint.Run(spec(tt.file), lint.Options{})
			if err == nil {
				t.Fatalf("Run(%s) returned no error", tt.file)
			}
			msg := err.Error()
			if strings.Contains(msg, "\n") {
				t.Errorf("error is not one line: %q", msg)
			}
			for _, w := range tt.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q does not mention %q", msg, w)
				}
			}
		})
	}
}

func TestRunKeepsSourceLinesWithoutCarriageReturns(t *testing.T) {
	report, err := lint.Run(spec("crlf.yaml"), lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	lines := report.Sources[spec("crlf.yaml")]
	if len(lines) != 10 {
		t.Fatalf("got %d source lines, want 10", len(lines))
	}
	if got, want := lines[6], "    get:"; got != want {
		t.Errorf("line 7 = %q, want %q", got, want)
	}
}

// kin-openapi records each element's file as a URL ("dir%20with%20space",
// "%5C" for Windows backslashes). Findings must use the path as the user
// wrote it, and it must be the key of the report's source lines.
func TestFindingsUseThePathAsGiven(t *testing.T) {
	path := spec("dir with space/no-auth.yaml")
	report, err := lint.Run(path, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(report.Findings))
	}
	if got := report.Findings[0].Location.File; got != path {
		t.Errorf("finding file = %q, want %q", got, path)
	}
	if _, ok := report.Sources[report.Findings[0].Location.File]; !ok {
		t.Errorf("no source lines for %q", report.Findings[0].Location.File)
	}
}

func TestSpecsSplitAcrossLocalFiles(t *testing.T) {
	path := spec("split/api.yaml")
	report, err := lint.Run(path, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (PRC001 on GET /orders)", len(report.Findings))
	}
	f := report.Findings[0]
	// The operation is written in paths/orders.yaml, line 1, column 1.
	want := spec("split/paths/orders.yaml")
	if f.Location.File != want || f.Location.Line != 1 || f.Location.Column != 1 {
		t.Errorf("location = %s:%d:%d, want %s:1:1", f.Location.File, f.Location.Line, f.Location.Column, want)
	}
	if _, ok := report.Sources[want]; !ok {
		t.Errorf("no source lines for %s, so no excerpt", want)
	}
}

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
	_, err := lint.Run(spec, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Run = %v, want an error refusing the symlink", err)
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
	report, err := lint.Run(spec, lint.Options{})
	for _, lines := range report.Sources {
		if strings.Contains(strings.Join(lines, "\n"), "STOLEN") {
			t.Fatal("Procyon read a file outside the spec's directory")
		}
	}
	if err == nil && len(report.Findings) > 0 {
		// Reading the decoy inside the directory is fine; the stolen file is not.
		t.Logf("read the decoy: %s", report.Findings[0].Location.File)
	}
}

// A $ref to an absolute path outside the allowed directories is refused
// without touching the file system: same message whether the file exists or
// not, so a spec cannot probe the machine running Procyon.
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
		_, err := lint.Run(spec, lint.Options{})
		if err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("Run = %v, want an error saying the $ref points outside", err)
		}
		msg := strings.ReplaceAll(err.Error(), filepath.ToSlash(target), "TARGET")
		messages = append(messages, strings.ReplaceAll(msg, dir, "DIR"))
	}
	for i := range messages {
		messages[i] = messages[i][strings.Index(messages[i], "$ref"):]
	}
	if messages[0] != messages[1] {
		t.Errorf("messages differ, revealing whether the file exists:\n %s\n %s", messages[0], messages[1])
	}
}

// writeSpec writes a spec at path whose /orders path item is a $ref.
func writeSpec(t *testing.T, path, ref string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n  /orders:\n    $ref: \"" + ref + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
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

const pathItem = "get:\n  responses:\n    \"200\":\n      description: OK\n"

// setHome points the user's home directory at dir for this test.
func setHome(t *testing.T, dir string) {
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // Windows
}

// A spec saved straight into the home directory must not make all of home
// (~/.ssh, ~/.config, ~/.aws) readable through $refs.
func TestRefsRefusedWhenTheSpecSitsInTheHomeDirectory(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	writeFile(t, filepath.Join(home, "notes.yaml"), pathItem)
	spec := filepath.Join(home, "api.yaml")
	writeSpec(t, spec, "./notes.yaml")
	_, err := lint.Run(spec, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Fatalf("Run = %v, want an error refusing $refs from the home directory", err)
	}
}

// Hidden files and directories are never read, even inside the root: a spec
// at a repository's top level sits next to .git, whose config may hold the
// CI's checkout token.
func TestRefsNeverReadHiddenFiles(t *testing.T) {
	setHome(t, t.TempDir())
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".git", "config"), pathItem)
	writeFile(t, filepath.Join(repo, ".env"), pathItem)
	for _, ref := range []string{"./.git/config", "./.env"} {
		spec := filepath.Join(repo, "api.yaml")
		writeSpec(t, spec, ref)
		_, err := lint.Run(spec, lint.Options{})
		if err == nil || !strings.Contains(err.Error(), "hidden") {
			t.Errorf("$ref %s: Run = %v, want an error refusing a hidden file", ref, err)
		}
	}
}

// By default $refs stay in the spec's directory. A monorepo whose specs
// share files from a sibling folder opts in with RefRoot.
func TestRefRootAllowsSiblingFoldersOnlyWhenAskedFor(t *testing.T) {
	setHome(t, t.TempDir())
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "common", "orders.yaml"), pathItem)
	spec := filepath.Join(repo, "specs", "api.yaml")
	writeSpec(t, spec, "../common/orders.yaml")

	_, err := lint.Run(spec, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "RefRoot") {
		t.Fatalf("default: Run = %v, want an error explaining how to allow it", err)
	}
	if _, err := lint.Run(spec, lint.Options{RefRoot: repo}); err != nil {
		t.Fatalf("with RefRoot: %v", err)
	}
}

// A $ref to a directory says so, instead of claiming it points outside.
func TestRefToADirectoryIsReportedAsSuch(t *testing.T) {
	setHome(t, t.TempDir())
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "orders"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(dir, "api.yaml")
	writeSpec(t, spec, "./orders")
	_, err := lint.Run(spec, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Run = %v, want an error saying it is not a regular file", err)
	}
}

// A symlink with an ordinary name must not lead to a hidden file: $refs
// never follow symlinks at all.
func TestRefsNeverFollowSymlinks(t *testing.T) {
	setHome(t, t.TempDir())
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".git", "config"), pathItem)
	writeFile(t, filepath.Join(repo, ".env"), pathItem)
	if err := os.Symlink(".git", filepath.Join(repo, "g")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if err := os.Symlink(".env", filepath.Join(repo, "e.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"./g/config", "./e.yaml"} {
		spec := filepath.Join(repo, "api.yaml")
		writeSpec(t, spec, ref)
		_, err := lint.Run(spec, lint.Options{})
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("$ref %s: Run = %v, want an error refusing the symlink", ref, err)
		}
	}
}

// A spec inside a hidden directory (.github) can still use $refs next to
// it, with or without RefRoot: only what comes after the spec's directory
// is checked for hidden parts.
func TestSpecInsideAHiddenDirectoryCanUseRefs(t *testing.T) {
	setHome(t, t.TempDir())
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".github", "orders.yaml"), pathItem)
	spec := filepath.Join(repo, ".github", "api.yaml")
	writeSpec(t, spec, "./orders.yaml")
	for _, opts := range []lint.Options{{}, {RefRoot: repo}} {
		if _, err := lint.Run(spec, opts); err != nil {
			t.Errorf("Options%+v: %v", opts, err)
		}
	}
}

// A $ref to the root directory itself is a directory, not a hidden file.
func TestRefToTheRootDirectoryIsNotAFile(t *testing.T) {
	setHome(t, t.TempDir())
	dir := t.TempDir()
	spec := filepath.Join(dir, "api.yaml")
	writeSpec(t, spec, "./")
	_, err := lint.Run(spec, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Run = %v, want an error saying it is not a regular file", err)
	}
}

// Short 8.3 names (GIT~1 for .git) exist on Windows, but also on FAT drives
// and SMB shares mounted on Linux and macOS: refused everywhere.
func TestRefsRefuseShortNamesOnEverySystem(t *testing.T) {
	setHome(t, t.TempDir())
	dir := t.TempDir()
	spec := filepath.Join(dir, "api.yaml")
	writeSpec(t, spec, "./GIT~1/config")
	_, err := lint.Run(spec, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "short") {
		t.Fatalf("Run = %v, want an error refusing a short name", err)
	}
}

// A RefRoot written through other directories than the spec's path is
// refused with a clear message: accepting it would mean checking $ref paths
// against one name of a directory while reading through another.
func TestRefRootWrittenThroughOtherDirectoriesIsRefused(t *testing.T) {
	setHome(t, t.TempDir())
	real := t.TempDir()
	writeFile(t, filepath.Join(real, "common", "orders.yaml"), pathItem)
	spec := filepath.Join(real, "specs", "api.yaml")
	writeSpec(t, spec, "../common/orders.yaml")
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	_, err := lint.Run(spec, lint.Options{RefRoot: alias})
	if err == nil || !strings.Contains(err.Error(), "the same way") {
		t.Fatalf("Run = %v, want an error asking to give both paths the same way", err)
	}
}

// The escape found in review: a symlink below RefRoot in the spec's path
// must not let the root be opened above RefRoot.
func TestRefRootCannotBeWidenedThroughASymlinkInTheSpecPath(t *testing.T) {
	setHome(t, t.TempDir())
	base := t.TempDir()
	refRoot := filepath.Join(base, "ci", "repo", "sub")
	writeFile(t, filepath.Join(refRoot, "a", "b", "c", "keep"), "")
	writeFile(t, filepath.Join(base, "secret.yaml"), pathItem)
	link := filepath.Join(base, "ci", "repo", "link")
	if err := os.Symlink(filepath.Join(refRoot, "a", "b", "c"), link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	spec := filepath.Join(link, "api.yaml")
	writeSpec(t, spec, "../../../secret.yaml")
	report, err := lint.Run(spec, lint.Options{RefRoot: refRoot})
	for file := range report.Sources {
		if strings.HasSuffix(file, "secret.yaml") {
			t.Fatal("read a file outside RefRoot")
		}
	}
	if err == nil {
		t.Fatal("Run returned no error")
	}
}

// Ordinary names with a tilde are fine; only short-name patterns (~1) are not.
func TestTildeInOrdinaryNamesIsAllowed(t *testing.T) {
	setHome(t, t.TempDir())
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "user~old.yaml"), pathItem)
	spec := filepath.Join(dir, "api.yaml")
	writeSpec(t, spec, "./user~old.yaml")
	if _, err := lint.Run(spec, lint.Options{}); err != nil {
		t.Fatalf("Run = %v, want no error for user~old.yaml", err)
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
	_, err := lint.Run(link, lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Run = %v, want an error refusing a symlinked spec", err)
	}
}

// Many fragment refs to one shared file are an ordinary layout: they must
// not exhaust the budget, since the file is read once.
func TestManyFragmentRefsToOneFileAreFine(t *testing.T) {
	setHome(t, t.TempDir())
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "common.yaml"), "components:\n  responses:\n    OK:\n      description: OK\n"+"      x-padding: \""+strings.Repeat("x", 400000)+"\"\n")
	spec := "openapi: 3.0.3\ninfo:\n  title: Shop\n  version: 1.0.0\npaths:\n"
	for i := 0; i < 200; i++ {
		spec += "  /p" + strconv.Itoa(i) + ":\n    get:\n      responses:\n        \"200\":\n          $ref: \"./common.yaml#/components/responses/OK\"\n"
	}
	path := filepath.Join(dir, "api.yaml")
	writeFile(t, path, spec)
	if _, err := lint.Run(path, lint.Options{}); err != nil {
		t.Fatalf("Run = %v, want no error", err)
	}
}

// Only real 8.3 names are refused: order~2024.yaml is an ordinary name.
func TestTildeFollowedByDigitsInLongNamesIsAllowed(t *testing.T) {
	setHome(t, t.TempDir())
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "order~2024.yaml"), pathItem)
	spec := filepath.Join(dir, "api.yaml")
	writeSpec(t, spec, "./order~2024.yaml")
	if _, err := lint.Run(spec, lint.Options{}); err != nil {
		t.Fatalf("Run = %v, want no error", err)
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
	_, err := lint.Run(filepath.Join("api", "openapi.yaml"), lint.Options{})
	if err == nil || !strings.Contains(err.Error(), "outside the working directory") {
		t.Fatalf("Run = %v, want an error refusing a spec reached through a link leading out", err)
	}
}
