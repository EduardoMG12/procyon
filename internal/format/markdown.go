package format

import (
	"fmt"
	"io"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"
)

// Markdown writes a summary for a CI job page ($GITHUB_STEP_SUMMARY on
// GitHub Actions): a table of counts, then findings, ignored findings and
// notes. Text that comes from the spec (paths, operations, ignore reasons)
// is escaped, so a spec cannot inject links, images or HTML into the page,
// nor reorder it with bidi controls.
//
// GitHub refuses a job summary over 1 MiB, and a large spec's report is
// more (docusign's: 2.7 MB), so the page stops at markdownLimit and says
// what it left out (see markdownPage).
func Markdown(w io.Writer, rep report.Report) error {
	p := markdownPage{limit: markdownLimit}
	markdownSummary(&p.Builder, rep)
	markdownFindings(&p, bySeverity(rep.Findings)) // most serious first, like the terminal
	markdownMatrix(&p, rep.Matrix)
	markdownIgnored(&p, rep.Ignored)
	markdownNotes(&p, rep.Notes)
	p.writeOmitted()
	_, err := io.WriteString(w, p.String())
	return err
}

// markdownLimit is the most bytes Markdown writes before its last line:
// 1 MiB, less 1 KiB for the line that says what was left out.
const markdownLimit = 1<<20 - 1<<10

// markdownPage is the Markdown being written, kept under limit. Entries (a
// finding, a row of the matrix, a note) are added whole and in order until
// one does not fit: that one and every entry after it are left out, and
// counted by kind for the page's last line. Only the page is cut: the
// summary above the entries counts every finding.
type markdownPage struct {
	strings.Builder
	limit   int
	omitted []omitted
}

// omitted counts the entries of one kind the page left out.
type omitted struct {
	count     int
	one, many string // the kind's name: "note", "notes"
}

// add writes entry, an entry of the kind named one (many in the plural),
// unless the page has started leaving entries out or entry does not fit.
func (p *markdownPage) add(one, many, entry string) {
	if len(p.omitted) == 0 && p.Len()+len(entry) <= p.limit {
		p.WriteString(entry)
		return
	}
	// The sections come one after another, so a kind seen before is the
	// last one counted.
	if n := len(p.omitted); n > 0 && p.omitted[n-1].one == one {
		p.omitted[n-1].count++
		return
	}
	p.omitted = append(p.omitted, omitted{count: 1, one: one, many: many})
}

// writeOmitted ends a page that left entries out: how many of each kind,
// and where to find them all.
func (p *markdownPage) writeOmitted() {
	if len(p.omitted) == 0 {
		return
	}
	counts := make([]string, len(p.omitted))
	for i, o := range p.omitted {
		name := o.many
		if o.count == 1 {
			name = o.one
		}
		counts[i] = fmt.Sprintf("%d %s", o.count, name)
	}
	list := counts[len(counts)-1]
	if len(counts) > 1 {
		list = strings.Join(counts[:len(counts)-1], ", ") + " and " + list
	}
	// The blank line keeps "---" a rule, not the underline of a heading.
	fmt.Fprintf(p, "\n---\n\n**Not shown:** %s. A GitHub job summary holds at most 1 MiB, "+
		"so this page shows the most serious findings first and stops there; the counts above include every one. "+
		"All of them are in the JSON or SARIF output.\n", list)
}

// markdownSummary writes the verdict and how many findings each severity
// has.
func markdownSummary(b *strings.Builder, rep report.Report) {
	verdict := "✅ passed"
	if rep.Failed {
		verdict = "❌ failed"
	}
	count := severityCounts(rep.Findings)
	fmt.Fprintf(b, "## Procyon: %s\n\n| Severity | Findings |\n|---|---|\n", verdict)
	for _, s := range []report.Severity{report.Critical, report.High, report.Medium, report.Low} {
		fmt.Fprintf(b, "| %s | %d |\n", s, count[s])
	}
	fmt.Fprintf(b, "| ignored | %d |\n\nThe run fails at **%s** or above.\n", len(rep.Ignored), rep.FailOn)
}

// markdownFindings writes each finding under a heading of its own: where it
// points, why it is a risk, how to fix it, and a runtime finding's proof.
func markdownFindings(p *markdownPage, findings []report.Finding) {
	for i, f := range findings {
		var b strings.Builder
		if i == 0 {
			b.WriteString("\n### Findings\n") // shown with the first entry, or not at all
		}
		fmt.Fprintf(&b, "\n#### %s · %s · %s\n\n%s", strings.ToUpper(f.Rule.Severity.String()), f.Rule.ID, escape(f.Rule.Title), code(location(f.Location)))
		if f.Operation != "" {
			b.WriteString(" · " + code(f.Operation))
		}
		fmt.Fprintf(&b, "\n\n**Why:** %s\n\n**Fix:** %s [More about %s](%s)\n", escape(f.Why), escape(f.Fix), f.Rule.ID, f.Rule.DocsURL())
		markdownEvidence(&b, f.Evidence)
		p.add("finding", "findings", b.String())
	}
}

// markdownEvidence lists the requests that prove a runtime finding: who
// sent what, the status, and the start of the body.
func markdownEvidence(b *strings.Builder, exchanges []report.Exchange) {
	if len(exchanges) > 0 {
		b.WriteString("\n**Proof:**\n\n")
	}
	for _, e := range exchanges {
		fmt.Fprintf(b, "- %s", code(exchangeLine(e)))
		if sent := flatten(e.Sent); sent != "" {
			b.WriteString(" sent " + code(sent))
		}
		if body := flatten(e.Body); body != "" {
			b.WriteString(" " + code(body))
		}
		b.WriteString("\n")
	}
}

// markdownIgnored lists the findings an x-procyon-ignore matched, each with
// its reason.
func markdownIgnored(p *markdownPage, ignored []report.IgnoredFinding) {
	for n, i := range ignored {
		var b strings.Builder
		if n == 0 {
			b.WriteString("\n### Ignored\n\n")
		}
		fmt.Fprintf(&b, "- **%s** %s", i.Finding.Rule.ID, code(location(i.Finding.Location)))
		if i.Finding.Operation != "" {
			b.WriteString(" " + code(i.Finding.Operation))
		}
		if i.Expires != "" {
			b.WriteString(" until " + escape(i.Expires))
		}
		b.WriteString(": " + escape(i.Reason) + "\n")
		p.add("ignored finding", "ignored findings", b.String())
	}
}

// markdownNotes lists what the reader should know that is not a finding.
func markdownNotes(p *markdownPage, notes []report.Note) {
	for i, n := range notes {
		header := ""
		if i == 0 {
			header = "\n### Notes\n\n"
		}
		p.add("note", "notes", fmt.Sprintf("%s- %s: %s\n", header, code(location(n.Location)), escape(n.Message)))
	}
}

// markdownMatrix writes a runtime test's authorization matrix: who got
// what from each operation.
func markdownMatrix(p *markdownPage, rows []report.MatrixRow) {
	for i, row := range rows {
		header := ""
		if i == 0 {
			header = "\n### Authorization matrix\n\n" +
				"What each caller got: ✅ allowed · 🚫 denied · 💥 server error · ❌ finding · 🌐 public · ⏭️ skipped (see notes) · 💤 unchanged since the base spec · – not tested\n\n" +
				"| Operation | A | B (A's objects) | Anonymous |\n|---|---|---|---|\n"
		}
		// A | splits a table cell even inside a code span: escape it.
		p.add("row of the authorization matrix", "rows of the authorization matrix", fmt.Sprintf("%s| %s | %s | %s | %s |\n",
			header, strings.ReplaceAll(code(row.Operation), "|", `\|`), markdownCell(row.A), markdownCell(row.B), markdownCell(row.Anonymous)))
	}
}

// icons draw the matrix's outcomes; NotCalled has none and is drawn "–".
var icons = map[report.Outcome]string{
	report.Allowed: "✅", report.Denied: "🚫", report.ServerError: "💥", report.Reached: "❌", report.Public: "🌐", report.Skipped: "⏭️", report.Unchanged: "💤",
}

func markdownCell(c report.Cell) string {
	icon := icons[c.Outcome]
	if icon == "" {
		return "–"
	}
	if c.Status != 0 {
		return fmt.Sprintf("%s %d", icon, c.Status)
	}
	return icon
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
// Hidden characters are shown before the Markdown escaping, which then
// keeps the backslash of \u202e as a backslash.
func escape(text string) string {
	return autolinks.Replace(markdownEscaper.Replace(visible(oneLine.Replace(text))))
}

// code wraps text in a code span whose backtick fence is longer than any
// run of backticks inside it, so the text can never close the span early.
// Line breaks become spaces, since a code span cannot cross blocks, and
// hidden characters are shown, as in the terminal.
func code(text string) string {
	text = visible(oneLine.Replace(text))
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
