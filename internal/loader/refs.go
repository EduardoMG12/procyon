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
	"runtime"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
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
	// maxRefTotal, reparsed the bytes kin-openapi parses again, against
	// maxRefReparsed, and reads the $refs resolved, against maxRefReads.
	total    int64
	reparsed int64
	reads    int
	// loaded holds the locations kin-openapi's document cache has been
	// handed, so a copy it drops unparsed is not counted (see handOver).
	loaded map[string]bool
	// overLimit is the error of the last $ref refused by maxRefReads or
	// maxRefReparsed. kin-openapi may report another error in its place
	// (when reading a file to parse it again fails, it returns the error
	// that made it parse again), so Load returns this one.
	overLimit error
	// specAbs is the spec's absolute path, for $refs back into it.
	specAbs string
	// escaped holds, by path, the escapes withLocations wrote into each
	// file kin-openapi was given, so columns can be mapped back.
	escaped map[string]escapes
}

func newSpecFiles(path, refRoot string, data []byte) *specFiles {
	files := &specFiles{
		spec: path, refRoot: refRoot,
		paths: map[string]string{}, lines: map[string][]string{},
		cache: map[string][]byte{}, cacheOwner: map[string]string{}, specData: data,
		escaped: map[string]escapes{},
		// kin-openapi's document cache starts with the spec, loaded first.
		loaded: map[string]bool{specURL(path).String(): true},
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
		loc.Column = f.escaped[given].original(loc.Line, loc.Column)
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
		f.overLimit = fmt.Errorf("$ref %q: the spec resolves more than %d $refs", path, maxRefReads)
		return nil, f.overLimit
	}
	if data, ok := f.cache[path]; ok {
		f.paths[location.String()] = f.cacheOwner[path]
		return f.handOver(location, path, data, false)
	}
	abs, err := filepath.Abs(path) // lexical: touches nothing
	if err != nil {
		return nil, fmt.Errorf("$ref %q: %w", path, err)
	}
	if abs == f.specAbs {
		// A $ref back into the spec, written another way (./api.yaml vs
		// api.yaml): it is the spec, already read.
		f.paths[location.String()] = f.spec
		f.cache[path], f.cacheOwner[path] = f.withLocations(f.spec, f.specData), f.spec
		return f.handOver(location, path, f.cache[path], false) // the spec was parsed first
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
	f.cache[path], f.cacheOwner[path] = f.withLocations(path, data), path
	return f.handOver(location, path, f.cache[path], true)
}

// handOver counts data against maxRefReparsed before kin-openapi gets it,
// unless it is a file's first copy (fresh from disk, counted against
// maxRefTotal): the cache makes reading a file again free, not parsing it.
// kin-openapi parses what it is handed, again and again: a $ref to a whole
// file (./error.yaml) parses it each time, and so does a $ref whose
// fragment it cannot find in its typed document (one into an x- extension
// of a header, say), which parses the file the $ref sits in. The one
// exception is its document cache: a $ref into a file (./common.yaml#/User)
// asks for the file each time, but only the first copy of each location is
// parsed. Counting the copies it drops would refuse a spec with many such
// $refs to one large shared file, which costs nothing.
func (f *specFiles) handOver(location *url.URL, path string, data []byte, firstCopy bool) ([]byte, error) {
	if kinCaller() == "(*Loader).loadFromURIInternal" {
		if f.loaded[location.String()] {
			return data, nil // dropped unparsed: kin-openapi has the document
		}
		f.loaded[location.String()] = true
	}
	if firstCopy {
		return data, nil
	}
	if f.reparsed += int64(len(data)); f.reparsed > maxRefReparsed {
		f.overLimit = fmt.Errorf("$ref %q: resolving the spec's $refs parses files again, more than %d MiB in total "+
			"(some $refs, such as ones to a whole file or into an x- extension, parse a file again each time)", path, maxRefReparsed>>20)
		return nil, f.overLimit
	}
	return data, nil
}

// kinCaller names the kin-openapi function that asked for a file, such as
// "(*Loader).loadFromURIInternal": the first kin-openapi frame on the stack
// past its readURL, which every request goes through. If kin-openapi renames
// the function, every copy is counted, and a test with many $refs into one
// shared file fails instead of a hostile spec getting through.
func kinCaller() string {
	const kin = "github.com/getkin/kin-openapi/openapi3."
	pcs := make([]uintptr, 16)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(0, pcs)])
	for {
		frame, more := frames.Next()
		if name, ok := strings.CutPrefix(frame.Function, kin); ok && name != "(*Loader).readURL" {
			return name
		}
		if !more {
			return ""
		}
	}
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

// withLocations returns the file at path, whose content is data, as
// kin-openapi is given it: with a trailing YAML comment. kin-openapi
// records locations only on its YAML path, and it tries JSON first; the
// comment makes the JSON attempt fail while the file stays valid YAML (JSON
// is YAML) with every line unchanged. Characters YAML cannot hold are
// escaped first (see escapeForYAML), and where is kept for asGiven.
func (f *specFiles) withLocations(path string, data []byte) []byte {
	data, f.escaped[path] = escapeForYAML(data)
	return append(data[:len(data):len(data)], "\n# procyon\n"...)
}

// specURL is the location kin-openapi is given for the spec at path, and so
// the one its origins report.
func specURL(path string) *url.URL {
	return &url.URL{Path: filepath.ToSlash(filepath.Clean(path))}
}
