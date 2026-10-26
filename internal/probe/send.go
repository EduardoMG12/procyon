package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/EduardoMG12/procyon/internal/loader"
	"github.com/EduardoMG12/procyon/internal/report"
)

// requestError is a request that could not be sent or answered: its
// message is masked, and errors.As still finds the cause (a timeout).
type requestError struct {
	msg string
	err error
}

func (e *requestError) Error() string { return e.msg }
func (e *requestError) Unwrap() error { return e.err }

// runner holds what every request of a run shares.
type runner struct {
	client *client
	target *url.URL
	tokens []string        // every token, to mask in evidence
	skip   map[string]bool // operations never called (test.skip)
	// redirects counts the answers that were redirects, and keeps the
	// first, for the note that says they were not followed.
	redirects     int
	firstRedirect string
}

// send calls one operation as who and records the exchange, with every
// token masked. A request that cannot be sent at all (the API is down, the
// budget is used up) stops the run: its findings would be incomplete.
func (r *runner) send(ctx context.Context, op loader.Operation, path string, who caller) (report.Exchange, error) {
	exchange, _, err := r.sendFull(ctx, op, path, who)
	return exchange, err
}

// sendFull is send, also returning the response body (up to maxResponse).
func (r *runner) sendFull(ctx context.Context, op loader.Operation, path string, who caller) (report.Exchange, []byte, error) {
	u := *r.target
	u.Path = strings.TrimSuffix(r.target.Path, "/") + path
	var body io.Reader
	if op.Method != http.MethodGet && op.Body != nil {
		body = bytes.NewReader(op.Body)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, u.String(), body)
	if err != nil {
		return report.Exchange{}, nil, fmt.Errorf("%s %s: %w", op.Method, op.Path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	authorize(req, op.Credential, who.token)
	resp, err := r.client.do(req)
	if err != nil {
		// The error may quote the URL, and a query-string token with it.
		return report.Exchange{}, nil, &requestError{msg: fmt.Sprintf("%s %s: %s", op.Method, op.Path, mask(err.Error(), r.tokens...)), err: err}
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return report.Exchange{}, nil, fmt.Errorf("%s %s: reading the response: %w", op.Method, op.Path, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		r.redirects++
		if r.firstRedirect == "" {
			r.firstRedirect = fmt.Sprintf("%s %s answered %d to %s", op.Method, mask(req.URL.RequestURI(), r.tokens...),
				resp.StatusCode, mask(resp.Header.Get("Location"), r.tokens...))
		}
	}
	exchange := report.Exchange{
		Caller: who.name,
		Method: op.Method,
		URL:    mask(req.URL.RequestURI(), r.tokens...),
		Status: resp.StatusCode,
		Body:   r.excerpt(string(got)),
	}
	if body != nil {
		exchange.Sent = r.excerpt(string(op.Body))
	}
	return exchange, got, nil
}

// excerpt is the start of a body for evidence, every token masked. Masked
// before it is cut: a token across the cut would otherwise leave its first
// characters unmasked.
func (r *runner) excerpt(body string) string {
	masked := mask(body, r.tokens...)
	if len(masked) <= maxBody {
		return masked
	}
	end := maxBody
	for end > 0 && !utf8.RuneStart(masked[end]) {
		end-- // never cut a character in half
	}
	return masked[:end]
}

// requestURI is how evidence shows a path sent to the target: with the
// target's own base path, as sendFull records it.
func (r *runner) requestURI(path string) string {
	return mask(strings.TrimSuffix(r.target.Path, "/")+path, r.tokens...)
}
