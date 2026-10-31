package loader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// notForYAML reports whether YAML cannot hold r as written, although JSON
// allows it in a string. kin-openapi parses every spec as YAML (see
// withLocations), and its parser refuses DEL, the C1 control characters
// and U+FFFE and U+FFFF, so one of them in a description refused the whole
// spec. It also reads NEL, U+2028 and U+2029 as line breaks, which changes
// the text and puts everything after one line further down.
func notForYAML(r rune) bool {
	return (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || r == 0xfffe || r == 0xffff
}

// escapes records where escapeForYAML wrote an escape: for each line of
// the file, the columns where the characters it replaced were, in order.
type escapes map[int][]int

// escapeForYAML writes each character notForYAML reports in a JSON text as
// a \u escape, which JSON and YAML both read as that same character. JSON
// allows none of them outside a string, so in valid JSON every one is in a
// string. Text that is not valid JSON, or needs no escape, is returned
// as it is. Lines stay the same; an escape takes six columns where the
// character took one, which escapes.original undoes.
func escapeForYAML(data []byte) ([]byte, escapes) {
	if !bytes.ContainsFunc(data, notForYAML) || !json.Valid(data) {
		return data, nil
	}
	out := make([]byte, 0, len(data)+64)
	found := escapes{}
	line, column := 1, 1 // kin-openapi counts columns in characters, from 1
	for rest := data; len(rest) > 0; {
		r, size := utf8.DecodeRune(rest)
		if notForYAML(r) {
			found[line] = append(found[line], column)
			out = fmt.Appendf(out, `\u%04x`, r)
		} else {
			out = append(out, rest[:size]...) // as written, even invalid UTF-8
		}
		rest = rest[size:]
		column++
		if r == '\n' {
			line, column = line+1, 1
		}
	}
	return out, found
}

// original maps a column of line in the escaped text back to the column in
// the file. Each escape before the column moved it five to the right.
func (e escapes) original(line, column int) int {
	shift := 0
	for _, at := range e[line] {
		if at+shift >= column {
			break
		}
		shift += len(`\u0000`) - 1
	}
	return column - shift
}
