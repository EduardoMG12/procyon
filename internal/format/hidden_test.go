package format_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/format"
	"github.com/EduardoMG12/procyon/internal/report"
)

// Characters that act on the screen instead of showing: written as Go
// escapes here so that this file shows them too.
const (
	rlo  = "\u202e"     // right-to-left override: reverses what follows
	lri  = "\u2066"     // left-to-right isolate
	zwsp = "\u200b"     // zero-width space
	tag  = "\U000e0041" // tag latin capital letter A, invisible
	nel  = "\u0085"     // C1 next line
	del  = "\x7f"       // delete
)

// hostile has every kind of hidden character in text that comes from the
// spec: the path, the file name, an ignore reason and a note.
func hostile() report.Report {
	f := report.Finding{
		Rule:      prc001,
		Location:  report.Location{File: "specs/sh" + zwsp + "op.yaml", Line: 9, Column: 5},
		Operation: "GET /files/" + rlo + "gpj.exe",
		Why:       "Anyone can call it.",
		Fix:       "Add security.",
	}
	return report.Report{
		FailOn:   report.High,
		Findings: []report.Finding{f},
		Ignored:  []report.IgnoredFinding{{Finding: f, Reason: "mirror " + lri + tag + nel + del}},
		Notes:    []report.Note{{Location: f.Location, Message: "ignore on GET /" + zwsp + "a matches no finding"}},
	}
}

// A bidi control or an invisible character from a spec is shown, never
// obeyed: in a CI log it could reorder a path ("Trojan Source"), and an
// invisible one could make two names look the same.
func TestFormatsShowHiddenCharacters(t *testing.T) {
	tests := []struct {
		name  string
		write func(*bytes.Buffer, report.Report) error
		shown []string // the hidden characters, as the output writes them
	}{
		{
			name: "terminal",
			write: func(b *bytes.Buffer, r report.Report) error {
				return format.Terminal(b, r, format.TerminalOptions{})
			},
			shown: []string{`sh\u200bop.yaml`, `/files/\u202egpj.exe`, `mirror \u2066\U000e0041\x85\x7f`, `GET /\u200ba`},
		},
		{
			// A code span keeps a backslash as it is; outside one, Markdown
			// escaping doubles it, so that it renders as one.
			name:  "markdown",
			write: func(b *bytes.Buffer, r report.Report) error { return format.Markdown(b, r) },
			shown: []string{`sh\u200bop.yaml`, `/files/\u202egpj.exe`, `mirror \\u2066\\U000e0041\\x85\\x7f`, `GET /\\u200ba`},
		},
		{
			// JSON doubles the backslash; the URI is percent-encoded.
			name:  "sarif",
			write: func(b *bytes.Buffer, r report.Report) error { return format.SARIF(b, r, "", nil) },
			shown: []string{`sh%E2%80%8Bop.yaml`, `/files/\\u202egpj.exe`, `mirror \\u2066\\U000e0041\\x85\\x7f`, `GET /\\u200ba`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bytes.Buffer
			if err := tt.write(&got, hostile()); err != nil {
				t.Fatal(err)
			}
			if strings.ContainsAny(got.String(), rlo+lri+zwsp+tag+nel+del) {
				t.Errorf("raw hidden characters reached the output: %q", got.String())
			}
			for _, want := range tt.shown {
				if !strings.Contains(got.String(), want) {
					t.Errorf("output does not show %s:\n%s", want, got.String())
				}
			}
		})
	}
}

// JSON keeps every value as it is: the hidden characters are \u escapes,
// which a script decodes back to the same strings.
func TestJSONEscapesHiddenCharactersWithoutChangingValues(t *testing.T) {
	var got bytes.Buffer
	if err := format.JSON(&got, hostile()); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got.String(), rlo+lri+zwsp+tag+nel+del) {
		t.Errorf("raw hidden characters reached the output: %q", got.String())
	}
	var decoded struct {
		Findings []struct {
			Location  struct{ File string }
			Operation string
		}
		Ignored []struct{ Reason string }
	}
	if err := json.Unmarshal(got.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	want := hostile()
	if f := decoded.Findings[0]; f.Location.File != want.Findings[0].Location.File || f.Operation != want.Findings[0].Operation {
		t.Errorf("decoded finding = %+v, want the spec's file and operation unchanged", f)
	}
	if decoded.Ignored[0].Reason != want.Ignored[0].Reason {
		t.Errorf("decoded reason = %q, want %q", decoded.Ignored[0].Reason, want.Ignored[0].Reason)
	}
}

// Accents, CJK and emoji are text, not hidden characters. An emoji made
// with zero-width joiners is the known cost: it shows as its parts.
func TestTerminalKeepsOtherUnicode(t *testing.T) {
	f := bola
	f.Operation = "GET /café/注文/🦝/👩" + "\u200d" + "💻"
	var got bytes.Buffer
	if err := format.Terminal(&got, report.Report{FailOn: report.High, Findings: []report.Finding{f}}, format.TerminalOptions{}); err != nil {
		t.Fatal(err)
	}
	if want := `GET /café/注文/🦝/👩\u200d💻`; !strings.Contains(got.String(), want) {
		t.Errorf("output does not contain %q:\n%s", want, got.String())
	}
}
