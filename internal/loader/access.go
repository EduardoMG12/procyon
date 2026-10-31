package loader

// What a spec can make Procyon read from disk: the spec itself
// (readSpec), the one directory its $refs may read from (openRefRoot), and
// the limits on both. specFiles.read, in refs.go, applies them to each $ref.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Limits on what a spec can make Procyon read and parse, so a hostile spec
// cannot exhaust a CI runner. Parsing costs many times a file's size in
// memory, so the limits stay well below what a runner holds. maxRefSize
// caps one file read through a $ref, maxRefTotal the bytes read from disk
// through all of them, maxRefReparsed the bytes kin-openapi parses again
// through all of them (a file read once may be parsed many times; as much
// as the largest spec), maxRefReads how many $refs are resolved, and
// maxSpecSize the spec itself. The variables are only variables so tests
// can lower them.
const maxRefSize = 10 << 20 // 10 MiB

var (
	maxRefTotal    int64 = 32 << 20 // 32 MiB
	maxRefReparsed int64 = 16 << 20 // 16 MiB
	maxRefReads          = 20000
	maxSpecSize    int64 = 16 << 20 // 16 MiB
)

// readSpec reads the spec, which must be a regular file (not a symlink to
// somewhere else, nor a device that never ends) of at most maxSpecSize.
func readSpec(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: file not found", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, unwrapPath(err))
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file (a symlink, directory or device); give the spec file itself", path)
	}
	if leavesWorkingDir(path) {
		return nil, fmt.Errorf("%s: reached through a link leading outside the working directory; give the spec's real path", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, unwrapPath(err))
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSpecSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if int64(len(data)) > maxSpecSize {
		return nil, fmt.Errorf("%s: larger than %d MiB", path, maxSpecSize>>20)
	}
	// Some Windows editors start a file with a byte order mark; YAML skips
	// it, JSON refuses it.
	return bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), nil
}

// unwrapPath drops the operation and path that os errors repeat, since the
// message already starts with the path.
func unwrapPath(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

// leavesWorkingDir reports whether a spec written inside the working
// directory really lives outside it, through a directory symlink: a pull
// request could commit such a link to make Procyon read, and root $refs
// in, a directory nobody reviews.
func leavesWorkingDir(path string) bool {
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return false
	}
	if _, inside := within(wd, dir); !inside {
		return false
	}
	_, stillInside := within(evalSymlinks(wd), evalSymlinks(dir))
	return !stillInside
}

// openRefRoot opens the one directory $refs may read from: refRoot when
// given (it must contain the spec), otherwise the spec's directory, and
// returns the spec's directory relative to it. It refuses a directory that
// would expose the whole machine: the file system's root, or the user's
// home directory or one containing it. That check runs on the directory
// actually opened, by identity, so another name for home (a symlink, a bind
// mount, a macOS firmlink, a Windows subst drive) is refused too.
func openRefRoot(spec, refRoot string) (*os.Root, string, error) {
	specDir, err := filepath.Abs(filepath.Dir(spec))
	if err != nil {
		return nil, "", err
	}
	dir := specDir
	if refRoot != "" {
		if dir, err = filepath.Abs(refRoot); err != nil {
			return nil, "", err
		}
	}
	specRel, ok := within(dir, specDir)
	if !ok {
		if _, same := within(evalSymlinks(dir), evalSymlinks(specDir)); same {
			// Matching only after resolving symlinks would mean opening one
			// directory while checking $ref paths against another name for
			// it; a symlink in between could widen the root. Refuse.
			return nil, "", fmt.Errorf("the $ref root %s and the spec %s are written through different directories; "+
				"give both the same way (for example both relative to the repository root)", dir, spec)
		}
		return nil, "", fmt.Errorf("the $ref root %s does not contain the spec", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	if reason := tooBroad(root); reason != "" {
		root.Close()
		return nil, "", fmt.Errorf("refusing $refs: %s is %s, and reading from it would expose the whole machine; "+
			"move the spec into a project directory", dir, reason)
	}
	return root, specRel, nil
}

// within reports whether child is parent or inside it, as text, and its
// path relative to parent.
func within(parent, child string) (rel string, ok bool) {
	rel, err := filepath.Rel(parent, child)
	if err != nil || !filepath.IsLocal(rel) {
		return "", false
	}
	return rel, true
}

// evalSymlinks returns path with symlinks resolved, or path itself if it
// cannot be.
func evalSymlinks(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return path
}
