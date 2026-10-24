# Procyon

Automatic security QA for APIs: it checks an API's description for security
problems before the API ships. This file is the glossary: use these words in
code, docs, issues and PRs.

## Language

**Spec**:
The API description Procyon reads: an OpenAPI 3.0/3.1 or Swagger 2.0 document,
in YAML or JSON, possibly split across local files.
_Avoid_: schema, contract, swagger file, definition

**Operation**:
One HTTP method on one path of the spec (`GET /users/{id}`).
_Avoid_: endpoint, route, handler

**Rule**:
One security check, with a stable ID (`PRC001`), a title, a severity and the
OWASP API Security Top 10 category it guards against.
_Avoid_: check, test, policy, scanner

**Finding**:
One place in the spec where a rule is broken.
_Avoid_: vulnerability, issue, alert, error, warning

**Severity**:
How serious a finding is: `critical`, `high`, `medium` or `low`. Set by the
rule, never by the user.
_Avoid_: level, priority

**Location**:
Where a finding points: file, line and column in the original spec, plus the
JSON pointer of the element.
_Avoid_: position, source

**Fail threshold**:
The lowest severity that fails a run (`--fail-on`, default `high`).
_Avoid_: strictness, gate level

**Ignore**:
An `x-procyon-ignore` entry on an operation that stops one rule from failing
the run there. It always has a reason and may have an expiry date.
_Avoid_: suppression, waiver, exception, allowlist

**Ignored finding**:
A finding matched by an ignore. It is still reported, in its own section, and
never fails the run.
_Avoid_: hidden finding, muted finding

**Public operation**:
An operation that is meant to be reachable without authentication, declared
with `x-procyon-public` and a reason.
_Avoid_: open endpoint, anonymous route

**Sensitive field**:
A schema property whose name marks it as a secret (password, token, secret,
hash, private key). Matched against a curated word list.
_Avoid_: secret field, credential

**PII field**:
A schema property whose name marks it as personal data (email, phone, CPF,
SSN, address, birth date). Matched against a curated word list.
_Avoid_: personal field, private data

**Report**:
Everything one run produced: findings, ignored findings, notes, and the
spec's summary.
_Avoid_: result, output, scan

**Format**:
One way of rendering a report: `terminal`, `json`, `sarif` or `markdown`.
_Avoid_: reporter, printer, output type

**Lint**:
The v0.1 way of running Procyon: read the spec only, never talk to a running
API.
_Avoid_: scan, audit, test

**Runtime test** (v0.2+, not built yet):
Running checks against a live copy of the API in a disposable environment.
_Avoid_: scan, attack, pentest
