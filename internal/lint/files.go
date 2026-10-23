package lint

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// specFiles is every file one spec was read from: the spec itself and the
// local files its $refs point to.
type specFiles struct {
	// paths maps the location kin-openapi records for a file (a URL: spaces
	// become %20, Windows backslashes %5C) to the path as Procyon read it.
	paths map[string]string
	// lines holds each file's lines, by path, for excerpts.
	lines map[string][]string
	// roots are the directories $refs may resolve into: the spec's own and
	// the working directory.
	roots []string
}

func newSpecFiles(path string, data []byte) (*specFiles, error) {
	files := &specFiles{paths: map[string]string{}, lines: map[string][]string{}}
	files.add(specURL(path), path, data)
	for _, dir := range []string{filepath.Dir(path), "."} {
		root, err := realPath(dir)
		if err != nil {
			return nil, err
		}
		files.roots = append(files.roots, root)
	}
	return files, nil
}

func (f *specFiles) add(location *url.URL, path string, data []byte) {
	f.paths[location.String()] = path
	f.lines[path] = splitLines(data)
}

// read is kin-openapi's file reader for $refs. A spec may come from anyone
// (a pull request, a vendor), so it reads only local files inside the
// spec's directory or the working directory, after resolving symlinks, and
// never the network.
func (f *specFiles) read(_ *openapi3.Loader, location *url.URL) ([]byte, error) {
	if location.Scheme != "" || location.Host != "" {
		return nil, fmt.Errorf("$ref %q is a URL: Procyon never fetches remote references while linting; download the file and refer to it by a local path", location)
	}
	path := filepath.FromSlash(location.Path)
	real, err := realPath(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("$ref %q: file not found", path)
	}
	if err != nil {
		return nil, fmt.Errorf("$ref %q: %w", path, err)
	}
	if !f.inside(real) {
		return nil, fmt.Errorf("$ref %q points outside the spec's directory and the working directory; Procyon only reads files there", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("$ref %q: %w", path, err)
	}
	f.add(location, path, data)
	return withLocations(data), nil
}

func (f *specFiles) inside(real string) bool {
	for _, root := range f.roots {
		if rel, err := filepath.Rel(root, real); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// realPath is the absolute path with every symlink resolved, so a link
// inside the repository cannot lead outside it.
func realPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
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
