# JSON format

`procyon lint --format json spec.yaml` (or `procyon test --format json`)
prints the whole report as JSON, and
`--output json=report.json` writes it to a file alongside the terminal
output. The exit code is the same whatever the format.

## Stability

`version` is the shape's version. Fields are only ever **added** within a
version; removing or renaming one bumps it. Scripts should check
`version == 1` and ignore fields they do not know.

## Shape (version 1)

```json
{
  "version": 1,
  "failed": true,
  "failOn": "high",
  "summary": { "critical": 0, "high": 1, "medium": 0, "low": 0, "ignored": 1 },
  "findings": [
    {
      "rule": {
        "id": "PRC001",
        "title": "Operation has no authentication",
        "severity": "high",
        "owasp": "API2:2023 Broken Authentication",
        "docs": "https://github.com/EduardoMG12/procyon/blob/main/docs/rules/PRC001.md"
      },
      "location": { "file": "specs/shop.yaml", "line": 9, "column": 5 },
      "operation": "GET /orders",
      "why": "Anyone who can reach the API can call this operation, ...",
      "fix": "Add a security requirement to the operation or to the whole spec."
    }
  ],
  "ignored": [
    { "rule": { "...": "..." }, "location": { "...": "..." },
      "why": "...", "fix": "...", "reason": "Internal mirror", "expires": "2027-01-31" }
  ],
  "notes": [
    { "location": { "file": "specs/shop.yaml", "line": 27, "column": 7 },
      "message": "ignore of PRC010 on GET /orders matches no finding; remove it" }
  ]
}
```

| Field | Meaning |
|---|---|
| `failed` | `true` when a finding is at or above `failOn`; then the exit code is `1` |
| `failOn` | The fail threshold used: `critical`, `high`, `medium` or `low` |
| `summary` | Findings per severity, and how many were ignored |
| `findings` | What is wrong, most serious first is **not** guaranteed: they are in file, line, column order |
| `findings[].operation` | `"GET /orders"`; absent for findings about no operation (a scheme, a server) |
| `findings[].evidence` | Runtime findings only (`procyon test`): the requests that prove it, in order, each `{caller, method, url, status, body, sent}`. `caller` is `"A"`, `"B"` or `"anonymous"`, `url` the path and query sent, `status` the HTTP status (`0` when the server never answered, as PRC103 reports), `body` the start of the response, `sent` the start of the request body (absent when there was none). Tokens are masked as `****`. Absent for lint findings |
| `ignored` | Findings an `x-procyon-ignore` matched, with its `reason` and optional `expires` |
| `notes` | What the run could not do or check, and why: expired or unused ignores, and for `procyon test` the operations not tested and the reason (no ID for A's object, TLS not checked on http, redirects). They never fail the run |
| `matrix` | `procyon test` only (absent for lint): one row per operation, `{operation, a, b, anonymous}`, each caller `{outcome, status}` and absent when not called. `outcome` is `allowed`, `denied` (not a 2xx nor a 5xx), `error` (a 5xx: the server failed), `finding`, `public`, `skipped` or `unchanged`; `status` is absent when there was no answer |

`file` always uses forward slashes, on every system. `findings`, `ignored`
and `notes` are always arrays, empty rather than missing.

Strings are the spec's and the API's text exactly, but characters that act
on a screen instead of showing (C1 controls, bidi controls such as U+202E,
invisible ones such as U+200B) are written as `\u` escapes, so the file is
safe to print in a terminal or a CI log. A JSON parser decodes them back to
the same characters.
