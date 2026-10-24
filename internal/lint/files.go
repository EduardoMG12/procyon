package lint

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// maxRefSize caps a file read through a $ref, so a reference to a huge
// generated file cannot exhaust a CI runner's memory.
const maxRefSize = 10 << 20 // 10 MiB

// specFiles is every file one spec was read from: the spec itself and the
// local files its $refs point to.
type specFiles struct {
	spec    string // the spec's path, as given
	refRoot string // Options.RefRoot, or "" for the spec's directory

	// paths maps the location kin-openapi records for a file (a URL, so a
	// space becomes %20) to the path as Procyon read it.
	paths map[string]string
	// lines holds each file's lines, by path, for excerpts.
	lines map[string][]string
	// cache holds $ref files by path, so a file referenced a thousand times
	// is read once.
	cache map[string][]byte
	// root is the one directory $refs may read from, opened on the first
	// $ref so a spec without $refs never depends on it.
	root *os.Root
	// specRel is the spec's directory relative to root ("." when they are
	// the same). Hidden parts are only refused after it.
	specRel string
}

func newSpecFiles(path, refRoot string, data []byte) *specFiles {
	files := &specFiles{
		spec: path, refRoot: refRoot,
		paths: map[string]string{}, lines: map[string][]string{}, cache: map[string][]byte{},
	}
	files.add(specURL(path), path, data)
	return files
}

func (f *specFiles) add(location *url.URL, path string, data []byte) {
	f.paths[location.String()] = path
	f.lines[path] = splitLines(data)
}

// close releases the directory opened for $refs.
func (f *specFiles) close() {
	if f.root != nil {
		f.root.Close()
		f.root = nil
	}
}

// read is kin-openapi's file reader for $refs, and the only way a $ref
// reaches the file system. A spec may come from anyone (a pull request, a
// vendor), so:
//
//  1. URLs are refused: linting never touches the network.
//  2. The path is cleaned and must lie, as text, inside the root (the
//     spec's directory, or Options.RefRoot) and contain no hidden file or
//     directory (.git, .env). These checks touch nothing, so a $ref cannot
//     probe the machine or reach a network share.
//  3. The file is opened through os.Root with that same cleaned path, which
//     refuses symlinks and ".." leading out of the root, and must be a
//     regular file of reasonable size.
func (f *specFiles) read(_ *openapi3.Loader, location *url.URL) ([]byte, error) {
	if location.Scheme != "" || location.Host != "" {
		return nil, fmt.Errorf("$ref %q is a URL: Procyon never fetches remote references while linting; download the file and refer to it by a local path", location)
	}
	path := filepath.Clean(filepath.FromSlash(location.Path))
	if data, ok := f.cache[path]; ok {
		f.paths[location.String()] = path
		return data, nil
	}
	if f.root == nil {
		root, specRel, err := openRefRoot(f.spec, f.refRoot)
		if err != nil {
			return nil, err
		}
		f.root, f.specRel = root, specRel
	}

	abs, err := filepath.Abs(path) // lexical: touches nothing
	if err != nil {
		return nil, fmt.Errorf("$ref %q: %w", path, err)
	}
	rel, err := filepath.Rel(f.root.Name(), abs)
	if err != nil || !filepath.IsLocal(rel) && rel != "." {
		return nil, fmt.Errorf("$ref %q points outside %s; Procyon only reads files there "+
			"(use --ref-root, or Options.RefRoot, to allow a directory containing both, such as the repository root)", path, f.root.Name())
	}
	if reason := refusedPart(rel, f.specRel); reason != "" {
		return nil, fmt.Errorf("$ref %q: %s", path, reason)
	}
	data, err := readRegular(f.root, rel)
	if err != nil {
		return nil, fmt.Errorf("$ref %q: %w", path, err)
	}
	f.add(location, path, data)
	f.cache[path] = withLocations(data)
	return f.cache[path], nil
}

// refusedPart explains why a path relative to the root may not be read
// as text, or returns "": a hidden part (.git, .env) after the spec's own
// directory, or, on Windows, a short 8.3 name (GIT~1) that could alias one.
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
		if runtime.GOOS == "windows" && strings.Contains(part, "~") {
			return "short (8.3) names are not allowed in $refs; use the full name"
		}
		if i >= own && strings.HasPrefix(part, ".") && part != "." {
			return "hidden files and directories (.git, .env, ...) are never read"
		}
	}
	return ""
}

// readRegular reads a regular file of at most maxRefSize through root. Every
// part of the path is checked with Lstat first: symlinks are never followed
// (a link with an ordinary name could lead to .git), and anything other
// than a regular file is refused before it is opened (a FIFO would block).
func readRegular(root *os.Root, rel string) ([]byte, error) {
	if rel == "." {
		return nil, errors.New("not a regular file")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for i := range parts {
		info, err := root.Lstat(filepath.Join(parts[:i+1]...))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("file not found")
		}
		if err != nil {
			return nil, errors.New("cannot be read")
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, errors.New("symlinks are not followed in $refs; refer to the file itself")
		}
		if i == len(parts)-1 {
			if !info.Mode().IsRegular() {
				return nil, errors.New("not a regular file")
			}
			if info.Size() > maxRefSize {
				return nil, fmt.Errorf("larger than %d MiB", maxRefSize>>20)
			}
		}
	}
	file, err := root.Open(rel)
	if err != nil {
		return nil, errors.New("cannot be read")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRefSize+1))
	if err != nil {
		return nil, errors.New("cannot be read")
	}
	if len(data) > maxRefSize {
		return nil, fmt.Errorf("larger than %d MiB", maxRefSize>>20) // it grew while being read
	}
	return data, nil
}

// openRefRoot opens the one directory $refs may read from: refRoot when
// given (it must contain the spec), otherwise the spec's directory, and
// returns the spec's directory relative to it. It
// refuses a directory that would expose the whole machine: the file
// system's root, or the user's home directory or one containing it.
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
	specRel, err := filepath.Rel(dir, specDir)
	if err != nil || !filepath.IsLocal(specRel) && specRel != "." {
		return nil, "", fmt.Errorf("the $ref root %s does not contain the spec", dir)
	}
	if reason := tooBroad(dir); reason != "" {
		return nil, "", fmt.Errorf("refusing $refs: %s is %s, and reading from it would expose the whole machine; "+
			"move the spec into a project directory", dir, reason)
	}
	root, err := os.OpenRoot(dir)
	return root, specRel, err
}

// tooBroad explains why dir may not be a $ref root, or returns "". Paths
// are compared with symlinks resolved, and without case on Windows and
// macOS.
func tooBroad(dir string) string {
	real := resolved(dir)
	if filepath.Dir(real) == real {
		return "the file system's root"
	}
	home := homeDir()
	if home == "" {
		return "" // unknown home: the root checks above still apply
	}
	if rel, err := filepath.Rel(real, resolved(home)); err == nil && (rel == "." || filepath.IsLocal(rel)) {
		if rel == "." {
			return "your home directory"
		}
		return "a directory containing your home directory"
	}
	return ""
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

// resolved returns dir with symlinks resolved, or dir itself if it cannot.
func resolved(dir string) string {
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	// Windows and macOS file systems usually ignore case: /Users/me and
	// /users/me are the same home directory.
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(dir)
	}
	return dir
}

// withLocations returns data with a trailing YAML comment. kin-openapi
// records locations only on its YAML path, and it tries JSON first; the
// comment makes the JSON attempt fail while the file stays valid YAML (JSON
// is YAML) with every line and column unchanged.
func withLocations(data []byte) []byte {
	return append(data[:len(data):len(data)], "\n# procyon\n"...)
}

// specURL is the location kin-openapi is given for the spec at path, and so
// the one its origins report.
func specURL(path string) *url.URL {
	return &url.URL{Path: filepath.ToSlash(path)}
}
