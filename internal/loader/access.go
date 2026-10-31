package loader

// What a spec can make Procyon read from disk, and how: the spec itself
// (readSpec), the one directory its $refs may read from (openRefRoot,
// tooBroad), which paths in it may be read (within, refusedPart), how a
// file is read (readRegular), and the limits on all of it. Every check
// that keeps a hostile spec from reading what it must not is in this
// file, so a security review reads one place. specFiles.read, in refs.go,
// applies them to each $ref.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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

// tooBroad explains why an opened root may not serve $refs, or returns "":
// it is the user's home directory, one of its ancestors, or the root of its
// file system. Directories are compared by identity, not by name.
func tooBroad(root *os.Root) string {
	opened, err := root.Stat(".")
	if err != nil {
		return "unreadable"
	}
	if fsRoot := filepath.VolumeName(root.Name()) + string(filepath.Separator); sameDir(opened, fsRoot) {
		return "the file system's root"
	}
	home := homeDir()
	if home == "" {
		return "" // unknown home: only the root check above applies
	}
	if sameDir(opened, home) {
		return "your home directory"
	}
	// The home's ancestors as written and as resolved (/home may be a link
	// to /usr/home): either way they contain it.
	for _, h := range []string{home, evalSymlinks(home)} {
		for dir := filepath.Dir(h); ; dir = filepath.Dir(dir) {
			if sameDir(opened, dir) {
				return "a directory containing your home directory"
			}
			if filepath.Dir(dir) == dir {
				break
			}
		}
	}
	return ""
}

func sameDir(opened fs.FileInfo, dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && os.SameFile(opened, info)
}

func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// shortName matches an 8.3 short name such as GIT~1 or PROGRA~2.EXE: up to
// six characters, a tilde, digits, and an extension of up to three.
// order~2024.yaml is an ordinary long name.
var shortName = regexp.MustCompile(`^[^.~]{1,6}~[0-9]+(\.[^.]{0,3})?$`)

// refusedPart explains why a path relative to the root may not be read
// as text, or returns "": a hidden part (.git, .env) after the spec's own
// directory, or a short 8.3 name (GIT~1) that could alias one. Short names
// exist on Windows, and also on FAT drives and SMB shares mounted anywhere.
func refusedPart(rel, specRel string) string {
	parts := strings.Split(rel, string(filepath.Separator))
	own := 0 // parts that belong to the spec's own directory
	if specRel != "." {
		specParts := strings.Split(specRel, string(filepath.Separator))
		if len(parts) > len(specParts) && slices.Equal(parts[:len(specParts)], specParts) {
			own = len(specParts)
		}
	}
	for i, part := range parts {
		if i < own {
			continue
		}
		if shortName.MatchString(part) {
			return "short (8.3) names are not allowed in $refs; use the full name"
		}
		if strings.HasPrefix(part, ".") && part != "." {
			return "hidden files and directories (.git, .env, ...) are never read"
		}
	}
	return ""
}

// readRegular reads a regular file of at most maxRefSize through root. Every
// part of the path is checked with Lstat first: symlinks are never followed
// (a link with an ordinary name could lead to .git), every part but the
// last must be a plain directory (not a Windows junction), and the last
// must be a regular file, checked before opening (a FIFO would block).
// After opening, the file must still be the one checked, so swapping it
// between the check and the read is caught.
func readRegular(root *os.Root, rel string) ([]byte, error) {
	if rel == "." {
		return nil, errors.New("not a regular file")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	var checked fs.FileInfo
	for i := range parts {
		info, err := root.Lstat(filepath.Join(parts[:i+1]...))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("file not found")
		}
		if err != nil {
			return nil, errors.New("cannot be read")
		}
		switch last := i == len(parts)-1; {
		case info.Mode()&fs.ModeSymlink != 0:
			return nil, errors.New("symlinks are not followed in $refs; refer to the file itself")
		case !last && !info.IsDir():
			return nil, errors.New("cannot be read (a part of the path is not a plain directory)")
		case last && !info.Mode().IsRegular():
			return nil, errors.New("not a regular file")
		case last && info.Size() > maxRefSize:
			return nil, fmt.Errorf("larger than %d MiB", maxRefSize>>20)
		}
		checked = info
	}
	file, err := root.Open(rel)
	if err != nil {
		return nil, errors.New("cannot be read")
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, checked) {
		return nil, errors.New("cannot be read (it changed while being checked)")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRefSize+1))
	if err != nil {
		return nil, errors.New("cannot be read")
	}
	if len(data) > maxRefSize {
		return nil, fmt.Errorf("larger than %d MiB", maxRefSize>>20) // it grew while being read
	}
	return data, nil
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
