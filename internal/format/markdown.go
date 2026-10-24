package format

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// Markdown writes a summary for a CI job page ($GITHUB_STEP_SUMMARY on
// GitHub Actions): a table of counts, then findings, ignored findings and
// notes. Text that comes from the spec (paths, operations, ignore reasons)
// is escaped, so a spec cannot inject links, images or HTML into the page.
func Markdown(w io.Writer, report lint.Report) error {
	var b strings.Builder
	verdict := "✅ passed"
	if report.Failed {
		verdict = "❌ failed"
	}
	count := map[lint.Severity]int{}
	for _, f := range report.Findings {
		count[f.Rule.Severity]++
	}
	fmt.Fprintf(&b, "## Procyon: %s\n\n| Severity | Findings |\n|---|---|\n", verdict)
	for _, s := range []lint.Severity{lint.Critical, lint.High, lint.Medium, lint.Low} {
		fmt.Fprintf(&b, "| %s | %d |\n", s, count[s])
	}
	fmt.Fprintf(&b, "| ignored | %d |\n\nThe run fails at **%s** or above.\n", len(report.Ignored), report.FailOn)

	findings := slices.Clone(report.Findings)
	// Most serious first, like the terminal; location order within each.
	slices.SortStableFunc(findings, func(a, b lint.Finding) int {
		return int(b.Rule.Severity) - int(a.Rule.Severity)
	})
	if len(findings) > 0 {
		b.WriteString("\n### Findings\n")
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "\n#### %s · %s · %s\n\n%s", strings.ToUpper(f.Rule.Severity.String()), f.Rule.ID, escape(f.Rule.Title), code(markdownLocation(f.Location)))
		if f.Operation != "" {
			b.WriteString(" · " + code(f.Operation))
		}
		fmt.Fprintf(&b, "\n\n**Why:** %s\n\n**Fix:** %s [More about %s](%s)\n", escape(f.Why), escape(f.Fix), f.Rule.ID, f.Rule.DocsURL())
	}

	if len(report.Ignored) > 0 {
		b.WriteString("\n### Ignored\n\n")
	}
	for _, i := range report.Ignored {
		fmt.Fprintf(&b, "- **%s** %s", i.Finding.Rule.ID, code(markdownLocation(i.Finding.Location)))
		if i.Finding.Operation != "" {
			b.WriteString(" " + code(i.Finding.Operation))
		}
		if i.Expires != "" {
			b.WriteString(" until " + escape(i.Expires))
		}
		b.WriteString(": " + escape(i.Reason) + "\n")
	}

	if len(report.Notes) > 0 {
		b.WriteString("\n### Notes\n\n")
	}
	for _, n := range report.Notes {
		fmt.Fprintf(&b, "- %s: %s\n", code(markdownLocation(n.Location)), escape(n.Message))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func markdownLocation(l lint.Location) string {
	return fmt.Sprintf("%s:%d:%d", filepath.ToSlash(l.File), l.Line, l.Column)
}

// markdownEscaper escapes the characters that make Markdown or HTML:
// emphasis, code, links, images, tags and table cells.
var markdownEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`,
	"[", `\[`, "]", `\]`, "<", `\<`, ">", `\>`, "|", `\|`,
)

func escape(text string) string {
	return markdownEscaper.Replace(text)
}

// code wraps text in a code span whose backtick fence is longer than any
// run of backticks inside it, so the text can never close the span early.
func code(text string) string {
	longest, run := 0, 0
	for _, r := range text {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if longest > 0 {
		return fence + text + " " + fence // a space keeps a trailing ` apart from the fence
	}
	return fence + text + fence
}
