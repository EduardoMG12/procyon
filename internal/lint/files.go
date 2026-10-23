package lint

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/getkin/kin-openapi/openapi3"
)

// specFiles is every file one spec was read from: the spec itself and the
// local files its $refs point to.
type specFiles struct {
	spec string // the spec's path, as given
	// paths maps the location kin-openapi records for a file (a URL: spaces
	// become %20, Windows backslashes %5C) to the path as Procyon read it.
	paths map[string]string
	// lines holds each file's lines, by path, for excerpts.
	lines map[string][]string
	// read caches $ref files by path, so a file referenced a thousand times
	// is read once.
	cache map[string][]byte
	// roots are the directories $refs may resolve into, opened lazily on the
	// first $ref so a spec without $refs never depends on them.
	roots []*os.Root
}

func newSpecFiles(path string, data []byte) *specFiles {
	files := &specFiles{spec: path, paths: map[string]string{}, lines: map[string][]string{}, cache: map[string][]byte{}}
	files.add(specURL(path), path, data)
	return files
}

func (f *specFiles) add(location *url.URL, path string, data []byte) {
	f.paths[location.String()] = path
	f.lines[path] = splitLines(data)
}

// read is kin-openapi's file reader for $refs, and the only way a $ref
// reaches the file system. A spec may come from anyone (a pull request, a
// vendor), so:
//
//  1. URLs are refused: linting never touches the network.
//  2. The path is cleaned and must lie, as text, inside an allowed
//     directory. This check touches nothing, so a $ref cannot probe the
//     machine, reach a network share, or learn whether a file exists.
//  3. The file is read through os.Root with that same cleaned path, which
//     refuses symlinks and ".." leading out of the directory.
func (f *specFiles) read(_ *openapi3.Loader, location *url.URL) ([]byte, error) {
	if location.Scheme != "" || location.Host != "" {
		return nil, fmt.Errorf("$ref %q is a URL: Procyon never fetches remote references while linting; download the file and refer to it by a local path", location)
	}
	path := filepath.FromSlash(location.Path)
	if data, ok := f.cache[path]; ok {
		return data, nil
	}
	outside := fmt.Errorf("$ref %q points outside the spec's directory; Procyon only reads files there and in the working directory that contains it", path)
	abs, err := filepath.Abs(path) // cleans the path; touches nothing
	if err != nil {
		return nil, outside
	}
	if f.roots == nil {
		if f.roots, err = openRoots(f.spec); err != nil {
			return nil, err
		}
	}
	for _, root := range f.roots {
		rel, err := filepath.Rel(root.Name(), abs)
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		data, err := root.ReadFile(rel)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("$ref %q: file not found", path)
		}
		if err != nil {
			return nil, outside // a symlink or ".." leading out of the root
		}
		f.add(location, path, data)
		f.cache[path] = withLocations(data)
		return f.cache[path], nil
	}
	return nil, outside
}

// close releases the directories opened for $refs.
func (f *specFiles) close() {
	for _, root := range f.roots {
		root.Close()
	}
	f.roots = nil
}

// openRoots opens the directories $refs may read from: the spec's own, and
// the working directory when it contains the spec (a monorepo whose specs
// share schemas from a sibling folder). The working directory is never a
// root when it is the file system's root or the user's home, where it would
// expose the whole machine.
func openRoots(spec string) ([]*os.Root, error) {
	specDir, err := filepath.Abs(filepath.Dir(spec))
	if err != nil {
		return nil, err
	}
	dirs := []string{specDir}
	if wd, err := os.Getwd(); err == nil && broadEnough(wd) {
		if rel, err := filepath.Rel(wd, specDir); err == nil && filepath.IsLocal(rel) && rel != "." {
			dirs = append(dirs, wd)
		}
	}
	var roots []*os.Root
	for _, dir := range dirs {
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", dir, err)
		}
		roots = append(roots, root)
	}
	return roots, nil
}

// broadEnough reports whether dir may serve as a root: not the file
// system's root (/, C:\) and not the user's home directory.
func broadEnough(dir string) bool {
	if filepath.Dir(dir) == dir {
		return false
	}
	home, err := os.UserHomeDir()
	return err != nil || filepath.Clean(home) != filepath.Clean(dir)
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
