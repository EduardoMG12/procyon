package format

import (
	"encoding/json"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/EduardoMG12/procyon/internal/lint"
)

// SARIF writes the report as SARIF 2.1.0, the format GitHub code scanning
// reads: findings show up in the repository's Security tab and as
// annotations on pull requests. rules is every rule Procyon has, declared
// in the log so results can point at their help. base is the directory
// file paths are made relative to: GitHub resolves them against the
// repository root, so the CLI passes the directory it runs in. An empty
// base keeps paths as they are.
//
// Ignored findings are results with an in-source suppression and its
// reason, so GitHub shows them as dismissed instead of losing them. Notes
// are tool notifications, not results.
func SARIF(w io.Writer, report lint.Report, base string, rules []lint.Rule) error {
	uri := artifactURI(base)
	index := map[string]int{}
	driver := sarifDriver{
		Name:           "Procyon",
		InformationURI: "https://github.com/EduardoMG12/procyon",
		Rules:          []sarifRule{},
	}
	for i, r := range rules {
		index[r.ID] = i
		driver.Rules = append(driver.Rules, sarifRule{
			ID:                   r.ID,
			Name:                 pascalCase(r.Title),
			ShortDescription:     sarifText{r.Title},
			HelpURI:              r.DocsURL(),
			Help:                 sarifText{"See " + r.DocsURL()},
			DefaultConfiguration: sarifConfig{sarifLevel(r.Severity)},
			Properties: sarifProperties{
				Tags:             []string{"security", r.OWASP},
				SecuritySeverity: securitySeverity(r.Severity),
			},
		})
	}
	run := sarifRun{
		Tool:        sarifTool{driver},
		Invocations: []sarifInvocation{{ExecutionSuccessful: true, Notifications: []sarifNotification{}}},
		Results:     []sarifResult{},
	}
	for _, n := range report.Notes {
		run.Invocations[0].Notifications = append(run.Invocations[0].Notifications, sarifNotification{
			Level: "note", Message: sarifText{n.Message}, Locations: []sarifLocation{sarifLoc(n.Location, uri)},
		})
	}
	for _, f := range report.Findings {
		run.Results = append(run.Results, sarifFinding(f, index, uri))
	}
	for _, i := range report.Ignored {
		r := sarifFinding(i.Finding, index, uri)
		r.Suppressions = []sarifSuppression{{Kind: "inSource", Justification: i.Reason}}
		run.Results = append(run.Results, r)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

func sarifFinding(f lint.Finding, index map[string]int, uri func(string) string) sarifResult {
	text := f.Why + " Fix: " + f.Fix
	if f.Operation != "" {
		text = f.Operation + ": " + text
	}
	for i, e := range f.Evidence {
		sep := " Proof: "
		if i > 0 {
			sep = "; "
		}
		text += sep + exchangeLine(e)
	}
	return sarifResult{
		RuleID:    f.Rule.ID,
		RuleIndex: index[f.Rule.ID],
		Level:     sarifLevel(f.Rule.Severity),
		Message:   sarifText{text},
		Locations: []sarifLocation{sarifLoc(f.Location, uri)},
	}
}

func sarifLoc(l lint.Location, uri func(string) string) sarifLocation {
	return sarifLocation{sarifPhysical{
		ArtifactLocation: sarifArtifact{URI: uri(l.File)},
		Region:           sarifRegion{StartLine: max(l.Line, 1), StartColumn: max(l.Column, 1)},
	}}
}

// artifactURI returns how to write a file's path as a SARIF URI: relative
// to base, each segment escaped (a space or "#" would break the URI), or an
// absolute file:// URI when the file is outside base.
func artifactURI(base string) func(file string) string {
	return func(file string) string {
		rel := file
		if base != "" {
			abs, err := filepath.Abs(file)
			if err == nil {
				rel, err = filepath.Rel(base, abs)
			}
			if err != nil || !filepath.IsLocal(rel) {
				return "file://" + (&url.URL{Path: filepath.ToSlash(abs)}).EscapedPath()
			}
		}
		segments := strings.Split(path.Clean(filepath.ToSlash(rel)), "/")
		for i, s := range segments {
			segments[i] = url.PathEscape(s)
		}
		return strings.Join(segments, "/")
	}
}

func sarifLevel(s lint.Severity) string {
	switch s {
	case lint.Critical, lint.High:
		return "error"
	case lint.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity is the score GitHub uses to label a security result
// critical (9.0+), high (7.0+), medium (4.0+) or low.
func securitySeverity(s lint.Severity) string {
	switch s {
	case lint.Critical:
		return "9.5"
	case lint.High:
		return "8.0"
	case lint.Medium:
		return "5.5"
	}
	return "2.0"
}

// pascalCase turns a title into a rule name: "Server URL does not use TLS"
// becomes "ServerURLDoesNotUseTLS".
func pascalCase(title string) string {
	var b strings.Builder
	for _, word := range strings.Fields(title) {
		runes := []rune(word)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	return b.String()
}

type (
	sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	sarifRun struct {
		Tool        sarifTool         `json:"tool"`
		Invocations []sarifInvocation `json:"invocations"`
		Results     []sarifResult     `json:"results"`
	}
	sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	sarifDriver struct {
		Name           string      `json:"name"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	sarifRule struct {
		ID                   string          `json:"id"`
		Name                 string          `json:"name"`
		ShortDescription     sarifText       `json:"shortDescription"`
		HelpURI              string          `json:"helpUri"`
		Help                 sarifText       `json:"help"`
		DefaultConfiguration sarifConfig     `json:"defaultConfiguration"`
		Properties           sarifProperties `json:"properties"`
	}
	sarifText struct {
		Text string `json:"text"`
	}
	sarifConfig struct {
		Level string `json:"level"`
	}
	sarifProperties struct {
		Tags             []string `json:"tags"`
		SecuritySeverity string   `json:"security-severity"`
	}
	sarifInvocation struct {
		ExecutionSuccessful bool                `json:"executionSuccessful"`
		Notifications       []sarifNotification `json:"toolExecutionNotifications"`
	}
	sarifNotification struct {
		Level     string          `json:"level"`
		Message   sarifText       `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	sarifResult struct {
		RuleID       string             `json:"ruleId"`
		RuleIndex    int                `json:"ruleIndex"`
		Level        string             `json:"level"`
		Message      sarifText          `json:"message"`
		Locations    []sarifLocation    `json:"locations"`
		Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	}
	sarifLocation struct {
		PhysicalLocation sarifPhysical `json:"physicalLocation"`
	}
	sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           sarifRegion   `json:"region"`
	}
	sarifArtifact struct {
		URI string `json:"uri"`
	}
	sarifRegion struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn"`
	}
	sarifSuppression struct {
		Kind          string `json:"kind"`
		Justification string `json:"justification"`
	}
)
