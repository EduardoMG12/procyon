package probe

import (
	"regexp"
	"strings"

	"github.com/EduardoMG12/procyon/internal/lint"
	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// signature is text that only a stack trace or a database error prints.
type signature struct {
	what string // "a Python stack trace", for the finding
	text *regexp.Regexp
}

// signatures are precise on purpose: the word "exception" in a message,
// or a field named "trace", is no internal error. Each one is what the
// platform itself prints, a frame of its stack, or an error code.
var signatures = []signature{
	{"a PHP error", regexp.MustCompile(`Fatal error(</b>)?:\s+Uncaught|Fatal error(</b>)?: .*\.php(</b>)? on line|Stack trace:\n#0 `)},
	{"a Python stack trace", regexp.MustCompile(`Traceback \(most recent call last\)`)},
	{"a Java stack trace", regexp.MustCompile(`Exception in thread "|(?m)^[ \t]+at [\w$./]+\(([\w$]+\.java:\d+|Native Method|Unknown Source)\)`)},
	{"a Node.js stack trace", regexp.MustCompile(`at Object\.<anonymous> \(|at Module\._compile \(|(?m)^[ \t]+at .*/\S+\.[cm]?js:\d+:\d+`)},
	{"a Go panic", regexp.MustCompile(`goroutine \d+ \[running\]|(?m)^panic: `)},
	{"a .NET stack trace", regexp.MustCompile(`System\.([A-Z]\w*\.)*\w*Exception\b|(?m)^[ \t]+at .+ in .+\.cs:line \d+`)},
	{"a Ruby stack trace", regexp.MustCompile("\\(most recent call first\\)|\\S+\\.rb:\\d+:in [`']")},
	{"a database error", regexp.MustCompile(`SQLSTATE\[|syntax error at or near |You have an error in your SQL syntax|ORA-\d{5}:|SQLite [Ee]rror|SQLITE_ERROR`)},
}

// unescaped undoes what JSON does to a trace inside a string: its lines
// are joined with \n (or \r\n), its frames indented with \t, and its
// backslashes, quotes, slashes and angle brackets escaped. Without it, a
// frame of a trace an API puts in a JSON field would never start a line.
// \\ comes first, so the \n of C:\\new stays a backslash and an n. A
// Windows line break, escaped or not, becomes a plain one.
var unescaped = strings.NewReplacer(`\\`, `\`, `\r`, "", "\r\n", "\n", `\n`, "\n", `\t`, "\t", `\"`, `"`, `\/`, "/",
	`\u003c`, "<", `\u003e`, ">", `\u0026`, "&")

// internalError finds the first signature in body, in the order of
// signatures, and returns what it is and where it starts: the matched text
// to the end of its line. what is "" when body holds none.
func internalError(body []byte) (what, line string) {
	text := unescaped.Replace(string(body))
	for _, s := range signatures {
		if at := s.text.FindStringIndex(text); at != nil {
			line, _, _ = strings.Cut(text[at[0]:], "\n")
			return s.what, strings.TrimSpace(line)
		}
	}
	return "", ""
}

// lookForInternalError keeps a PRC109 finding when body, op's answer, holds
// an internal error, unless op already has one: the first answer that
// shows it is enough. Its evidence is the exchange with the line that
// matched instead of the start of the body, every token masked and cut to
// the length of an excerpt.
func (r *runner) lookForInternalError(op loader.Operation, exchange report.Exchange, body []byte) {
	what, line := internalError(body)
	if what == "" || r.withInternalError[op.Key()] {
		return
	}
	r.withInternalError[op.Key()] = true
	exchange.Body = r.excerpt(line)
	r.internalErrors = append(r.internalErrors, report.Finding{
		Rule: lint.RuntimeRule("PRC109"), Location: op.Location, Operation: op.Key(),
		Why: "The answer holds " + what + ": it shows how the server is built (file paths, libraries, queries) " +
			"and tells an attacker where to aim.",
		Fix:      "Log the details on the server and answer with a short message and the right status. Turn off debug output in every deployment.",
		Evidence: []report.Exchange{exchange},
	})
}

// internalErrorsUnderTest are the PRC109 findings of the operations under
// test: those changed since --base-spec, or every one when changed is nil.
// Discovery reads unchanged operations too, for IDs, and their answers are
// looked at like any other; they are just not reported.
func (r *runner) internalErrorsUnderTest(changed map[string]bool) []report.Finding {
	var kept []report.Finding
	for _, f := range r.internalErrors {
		if changed == nil || changed[f.Operation] {
			kept = append(kept, f)
		}
	}
	return kept
}
