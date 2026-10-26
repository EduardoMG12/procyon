package format

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"
)

// Markdown writes a summary for a CI job page ($GITHUB_STEP_SUMMARY on
// GitHub Actions): a table of counts, then findings, ignored findings and
// notes. Text that comes from the spec (paths, operations, ignore reasons)
// is escaped, so a spec cannot inject links, images or HTML into the page.
func Markdown(w io.Writer, rep report.Report) error {
	var b strings.Builder
	verdict := "✅ passed"
	if rep.Failed {
		verdict = "❌ failed"
	}
	count := map[report.Severity]int{}
	for _, f := range rep.Findings {
		count[f.Rule.Severity]++
	}
	fmt.Fprintf(&b, "## Procyon: %s\n\n| Severity | Findings |\n|---|---|\n", verdict)
	for _, s := range []report.Severity{report.Critical, report.High, report.Medium, report.Low} {
		fmt.Fprintf(&b, "| %s | %d |\n", s, count[s])
	}
	fmt.Fprintf(&b, "| ignored | %d |\n\nThe run fails at **%s** or above.\n", len(rep.Ignored), rep.FailOn)

	findings := slices.Clone(rep.Findings)
	// Most serious first, like the terminal; location order within each.
	slices.SortStableFunc(findings, func(a, b report.Finding) int {
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
		if len(f.Evidence) > 0 {
			b.WriteString("\n**Proof:**\n\n")
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "- %s", code(exchangeLine(e)))
			if sent := flatten(e.Sent); sent != "" {
				b.WriteString(" sent " + code(sent))
			}
			if body := flatten(e.Body); body != "" {
				b.WriteString(" " + code(body))
			}
			b.WriteString("\n")
		}
	}

	matrix(&b, rep.Matrix)

	if len(rep.Ignored) > 0 {
		b.WriteString("\n### Ignored\n\n")
	}
	for _, i := range rep.Ignored {
		fmt.Fprintf(&b, "- **%s** %s", i.Finding.Rule.ID, code(markdownLocation(i.Finding.Location)))
		if i.Finding.Operation != "" {
			b.WriteString(" " + code(i.Finding.Operation))
		}
		if i.Expires != "" {
			b.WriteString(" until " + escape(i.Expires))
		}
		b.WriteString(": " + escape(i.Reason) + "\n")
	}

	if len(rep.Notes) > 0 {
		b.WriteString("\n### Notes\n\n")
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "- %s: %s\n", code(markdownLocation(n.Location)), escape(n.Message))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// matrix writes a runtime test's authorization matrix: who got what from
// each operation.
func matrix(b *strings.Builder, rows []report.MatrixRow) {
	if len(rows) == 0 {
		return
	}
	b.WriteString("\n### Authorization matrix\n\n" +
		"What each caller got: ✅ allowed · 🚫 denied · ❌ finding · 🌐 public · ⏭️ skipped (see notes) · 💤 unchanged since the base spec · – not tested\n\n" +
		"| Operation | A | B (A's objects) | Anonymous |\n|---|---|---|---|\n")
	for _, row := range rows {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", code(row.Operation), cell(row.A), cell(row.B), cell(row.Anonymous))
	}
}

// icons draw the matrix's outcomes; NotCalled has none and is drawn "–".
var icons = map[report.Outcome]string{
	report.Allowed: "✅", report.Denied: "🚫", report.Reached: "❌", report.Public: "🌐", report.Skipped: "⏭️", report.Unchanged: "💤",
}

func cell(c report.Cell) string {
	icon := icons[c.Outcome]
	if icon == "" {
		return "–"
	}
	if c.Status != 0 {
		return fmt.Sprintf("%s %d", icon, c.Status)
	}
	return icon
}

func markdownLocation(l report.Location) string {
	return fmt.Sprintf("%s:%d:%d", filepath.ToSlash(l.File), l.Line, l.Column)
}

// oneLine turns line breaks into spaces: a new line could end a list item
// or a code span and start a heading of the spec's choosing.
var oneLine = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

// markdownEscaper escapes the characters that make Markdown or HTML:
// emphasis, code, links, images, tags and table cells.
var markdownEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`,
	"[", `\[`, "]", `\]`, "<", `\<`, ">", `\>`, "|", `\|`,
)

// autolinks are what GitHub turns into links even without brackets: URLs,
// www. addresses and email addresses. Escaping one character of each keeps
// them as plain text.
var autolinks = strings.NewReplacer("://", `:\/\/`, "www.", `www\.`, "WWW.", `WWW\.`, "@", `\@`)

// escape makes text from the spec safe to place in Markdown as plain text.
func escape(text string) string {
	return autolinks.Replace(markdownEscaper.Replace(oneLine.Replace(text)))
}

// code wraps text in a code span whose backtick fence is longer than any
// run of backticks inside it, so the text can never close the span early.
// Line breaks become spaces, since a code span cannot cross blocks.
func code(text string) string {
	text = oneLine.Replace(text)
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
	if strings.HasPrefix(text, "`") || strings.HasSuffix(text, "`") {
		// A space keeps a backtick at either end apart from the fence.
		return fence + " " + text + " " + fence
	}
	return fence + text + fence
}
