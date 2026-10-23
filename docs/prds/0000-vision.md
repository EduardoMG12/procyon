# 0000 — Procyon Vision

> Status: **draft** · Owner: EduardoMG12 · Last updated: 2026-10-23
>
> This is the map. Milestone PRDs (`0001`, `0002`, …) are the territory.
> When they disagree, the milestone PRD wins and this file gets updated.

## Goals

Procyon is **automatic security QA for APIs**. Unit and integration tests ask
"does the API do what it should?". Procyon asks "can the API be misused?",
and it does so without the developer writing a single test case: the
expectations it checks are the same for every API (operations require
authentication, users cannot reach each other's data, secrets never appear in
responses).

It runs in CI as a quality gate, next to the test suite, and fails the build
when it finds something serious.

It is a **defensive tool for authorized testing**. It reads specs, and from
v0.2 tests running APIs, that the user owns or has explicit permission to
test. It is never pointed at someone else's production system.

Long-term "done": a small team with no security engineer adds one line to its
CI and from then on learns about authorization holes in its API from a
failing build, with an explanation it understands and a fix it can apply,
instead of from an incident.

## Who it is for

Developers and small teams **without a security team**. They will not read a
manual, tune a scanner or decode jargon. Tools like OWASP ZAP and Nuclei are
powerful but built for security specialists; Procyon competes on developer
experience, not on the number of checks.

## Principles

1. **Language-agnostic.** Procyon reads the spec and, from v0.2, talks HTTP
   to a running API. It never reads source code: it works for an API written
   in any language, and it does not become a SAST tool (Semgrep and CodeQL
   own that space).
2. **Zero-config by default.** `procyon lint openapi.yaml` works with no
   config file. Every option has a sensible default.
3. **Correct before broad.** Few rules, each one deterministic, documented
   and tested against real specs. A missed problem gives false confidence,
   which is worse than no tool at all. A noisy rule gets the tool switched
   off. Both are bugs.
4. **Every finding teaches.** Each finding says where it is (file, line,
   column), why it is a risk, and how to fix it, in plain words.
5. **Deterministic.** The same spec and the same Procyon version always give
   the same report. No network access while linting.
6. **Exceptions are visible.** A user can silence a finding, but only with a
   written reason, and the silenced finding keeps appearing in the report.

## Milestones

| Milestone | What it does | Where it runs | PRD |
|---|---|---|---|
| **v0.1 — Lint** | Reads the spec and reports security problems in the API's *design* | CI, on every PR | [0001](0001-v0.1-spec-lint.md) |
| **v0.2 — Runtime tests** | Starts a disposable copy of the API (Docker) with seeded test accounts, checks that user A's objects are unreachable by user B and by anonymous callers (BOLA), checks TLS, checks that malformed input is rejected, then tears everything down. Only tests operations changed in the PR. Posts a PR comment with an authorization matrix | CI, on every PR | not written |
| **v0.3 — Security QA environment** | Runs continuously against a permanent security-QA environment (next to staging and prod), keeps history and trends, reads the spec from a URL | A long-lived environment | not written |

v0.2 is the differentiator: existing runtime tools expect the user to provide
a running API; Procyon will start the throwaway environment itself. v0.1 is
useful on its own and lays the foundation (spec loading, locations, rules,
report formats, ignores) that v0.2 builds on. The `x-procyon-public` marker
introduced in v0.1 is exactly what v0.2 needs to know which operations may be
called anonymously.

## Architecture

- **One binary: `procyon`**, built for Linux, macOS and Windows. Subcommands
  per milestone: `procyon lint` (v0.1), `procyon test` (v0.2).
- **A library under the CLI.** The CLI only parses flags, calls the library
  and writes the formats. Other Go programs can call the same library.
- **The core knows nothing about formats.** Rules produce findings; the
  engine applies ignores and the fail threshold and returns a report; formats
  turn a report into bytes. Adding a format never touches a rule, and adding a
  rule never touches a format.
- **Locations come from the loader.** The spec is loaded once, with the
  file/line/column of every element recorded. Rules ask for locations; they
  never re-parse YAML.

```
           ┌──────────┐     ┌────────┐     ┌────────┐     ┌──────────┐
spec ────▶ │  Loader  │ ──▶ │ Rules  │ ──▶ │ Engine │ ──▶ │ Formats  │ ──▶ terminal / json /
files      │ + locs   │     │ PRC0xx │     │ignores,│     │          │     sarif / markdown
           └──────────┘     └────────┘     │fail-on │     └──────────┘
                                           └────────┘
```

### Stack

- Go (latest stable), standard library first.
- Spec loading: `github.com/getkin/kin-openapi`. It parses OpenAPI 3.0 and
  3.1, records file/line/column for every element, resolves local `$ref`s
  across files and lets Procyon refuse remote ones. It also converts Swagger
  2.0 to OpenAPI 3.0, but the converted document loses its locations, so
  Swagger 2.0 needs extra work (PRD 0001).
- Each other dependency is justified in its PR (see CONTRIBUTING.md).

## Not goals

- Reading or analysing source code (SAST).
- Being a general-purpose scanner for websites, networks or hosts.
- Testing systems the user does not own or is not authorized to test.
- A hosted service or dashboard before v0.3.
