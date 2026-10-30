package loader

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// Limits on what a spec can make Procyon read and parse, so a hostile spec
// cannot exhaust a CI runner. Parsing costs many times a file's size in
// memory, so the limits stay well below what a runner holds. maxRefSize
// caps one file read through a $ref, maxRefTotal the bytes read from disk
// through all of them, maxRefReads how many $refs are resolved (each may be
// parsed again), and maxSpecSize the spec itself. The variables are only
// variables so tests can lower them.
const maxRefSize = 10 << 20 // 10 MiB

var (
	maxRefTotal int64 = 32 << 20 // 32 MiB
	maxRefReads       = 20000
	maxSpecSize int64 = 16 << 20 // 16 MiB
)

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
	// is read from disk once, and cacheOwner the path findings use for it.
	cache      map[string][]byte
	cacheOwner map[string]string
	// specData is the spec's own content, for $refs that point back into it.
	specData []byte
	// back maps a position in a converted Swagger 2.0 spec to the original
	// file; nil for OpenAPI 3 specs.
	back func(position) (position, bool)
	// root is the one directory $refs may read from, opened on the first
	// $ref so a spec without $refs never depends on it.
	root *os.Root
	// specRel is the spec's directory relative to root ("." when they are
	// the same). Hidden parts are only refused after it.
	specRel string
	// total counts the bytes read from disk through $refs, against
	// maxRefTotal, and reads the $refs resolved, against maxRefReads.
	total int64
	reads int
	// specAbs is the spec's absolute path, for $refs back into it.
	specAbs string
}

func newSpecFiles(path, refRoot string, data []byte) *specFiles {
	files := &specFiles{
		spec: path, refRoot: refRoot,
		paths: map[string]string{}, lines: map[string][]string{},
		cache: map[string][]byte{}, cacheOwner: map[string]string{}, specData: data,
	}
	files.specAbs, _ = filepath.Abs(path)
	files.add(specURL(path), path, data)
	return files
}

func (f *specFiles) add(location *url.URL, path string, data []byte) {
	f.paths[location.String()] = path
	f.lines[path] = splitLines(data)
}

// asGiven turns the file URL kin-openapi records in a location back into
// the path Procyon read and, for a Swagger 2.0 spec, the position in the
// converted document back into the original file.
func (f *specFiles) asGiven(loc report.Location) report.Location {
	if given, ok := f.paths[loc.File]; ok {
		loc.File = given
		if given == f.spec && f.back != nil {
			if p, ok := f.back(position{loc.Line, loc.Column}); ok {
				loc.Line, loc.Column = p.line, p.column
			}
		}
	}
	return loc
}

// close releases the directory opened for $refs.
func (f *specFiles) close() {
	if f.root != nil {
		f.root.Close()
		f.root = nil
	}
}

// localPath returns the file path a $ref location names, or false for a
// URL. url.Parse reads a Windows drive letter as a scheme (c:/specs/a.yaml
// has scheme "c"), so a one-letter scheme that this system takes for a
// volume is a path; it then goes through the same checks as any other.
func localPath(location *url.URL) (string, bool) {
	if location.Host != "" {
		return "", false
	}
	if location.Scheme == "" {
		return location.Path, true
	}
	if drive := location.Scheme + ":" + location.Path; len(location.Scheme) == 1 && filepath.VolumeName(drive) != "" {
		return drive, true
	}
	return "", false
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
	local, ok := localPath(location)
	if !ok {
		return nil, fmt.Errorf("$ref %q is a URL: Procyon never fetches remote references while linting; download the file and refer to it by a local path", location)
	}
	path := filepath.Clean(filepath.FromSlash(local))
	if f.reads++; f.reads > maxRefReads {
		return nil, fmt.Errorf("$ref %q: the spec resolves more than %d $refs", path, maxRefReads)
	}
	if data, ok := f.cache[path]; ok {
		f.paths[location.String()] = f.cacheOwner[path]
		return data, nil
	}
	abs, err := filepath.Abs(path) // lexical: touches nothing
	if err != nil {
		return nil, fmt.Errorf("$ref %q: %w", path, err)
	}
	if abs == f.specAbs {
		// A $ref back into the spec, written another way (./api.yaml vs
		// api.yaml): it is the spec, already read.
		f.paths[location.String()] = f.spec
		f.cache[path], f.cacheOwner[path] = withLocations(f.specData), f.spec
		return f.cache[path], nil
	}
	if f.root == nil {
		root, specRel, err := openRefRoot(f.spec, f.refRoot)
		if err != nil {
			return nil, err
		}
		f.root, f.specRel = root, specRel
	}

	rel, ok := within(f.root.Name(), abs)
	if !ok {
		return nil, fmt.Errorf("$ref %q points outside %s; Procyon only reads files there "+
			"(allow a directory containing both with --ref-root, or Options.RefRoot, such as the repository root)", path, f.root.Name())
	}
	if reason := refusedPart(rel, f.specRel); reason != "" {
		return nil, fmt.Errorf("$ref %q: %s", path, reason)
	}
	data, err := readRegular(f.root, rel)
	if err != nil {
		return nil, fmt.Errorf("$ref %q: %w", path, err)
	}
	if f.total += int64(len(data)); f.total > maxRefTotal {
		return nil, fmt.Errorf("$ref %q: the spec's $refs read more than %d MiB in total", path, maxRefTotal>>20)
	}
	f.add(location, path, data)
	f.cache[path], f.cacheOwner[path] = withLocations(data), path
	return f.cache[path], nil
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
	return &url.URL{Path: filepath.ToSlash(filepath.Clean(path))}
}
