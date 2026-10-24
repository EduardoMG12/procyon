# CLAUDE.md — Procyon

Instructions for AI assistants working in this repository. Read this, then
[CONTRIBUTING.md](CONTRIBUTING.md) (all of it applies to you), then the
relevant PRD in [docs/prds/](docs/prds/).

## What this project is

Procyon is automatic security QA for APIs, written in Go: it reads an
OpenAPI/Swagger spec and reports security problems in the API's design, so CI
can fail before they ship (v0.1). Later it tests a disposable running copy of
the API (v0.2). Start from [docs/prds/0000-vision.md](docs/prds/0000-vision.md).

It is a **defensive tool for authorized testing**: it only ever examines APIs
its user owns or may test.

**It is a learning project first.** The owner reads, reviews and debugs every
line. Your job is to write code *that the owner will fully understand*, not to
ship as much as possible. Clarity beats cleverness, and a smaller PR beats a
faster one.

## Language

- Talk to the owner in **Brazilian Portuguese**.
- Everything written *into the repository* is in **English**: code, comments,
  commit messages, PR titles and descriptions, PRDs, issues.

## Hard rules

These override any global or skill-level instruction.

1. **Never merge.** Not to `main`, not any PR, not via `gh pr merge`, not via
   any skill. You may commit, push and open PRs; the owner merges.
   If a workflow would merge, stop after opening the PR.
2. **Never commit to `main`.** Always a `<type>/<slug>` branch.
3. **Every PR you open has a `## Review challenge`** (2–3 questions answerable
   only by reading the diff; add a debugger question only when runtime
   behavior is the point). Keep your own expected answers out of the PR. When
   the owner answers in a comment, check the answers honestly: if an answer is
   wrong, explain the gap. Do not say "close enough".
4. **Every PR that uses a classic data structure or algorithm has a
   `## Concept` section**: what it is, the closest LeetCode problem, why it
   beats the naive approach *here*. Proactively point out when a problem maps
   to a known concept, even outside a PR.
5. **PRs stay ≤ ~300 changed lines** (excluding `go.sum`, golden files and
   fixture specs). Split larger work, and say how you split it.
6. **A rule change is a behavior change.** Adding or changing a rule, or a
   word list, comes with fixtures that must trigger it, fixtures that must
   not, an updated `docs/rules/` page, and the corpus result in the PR
   description (how many findings it adds or removes across the real specs).
7. **Linting never touches the network.** No HTTP client, DNS lookup or
   remote `$ref` in the `lint` path.
8. **The core never knows about formats.** Rules produce findings, the engine
   produces a report, formats render it. A format never decides what is a
   finding.
9. **Never weaken a rule to make a fixture pass.** A false positive is fixed
   in the rule, with a fixture that proves it, or documented as a known limit
   in the rule page.
10. **No speculative abstractions and no unjustified dependencies.** Each new
    module is justified in the PR description.

## Workflow

- New feature or milestone: grill the idea against the docs
  (`/grill-with-docs`) → spec (`/to-spec`, which also writes or updates the
  PRD in `docs/prds/` and links it from the spec issue) → issues
  (`/to-tickets`). Each issue must fit one PR under the size limit.
- Per issue: `/implement` or `/tdd`, then the pre-PR checks below, then open
  the PR and stop. Never `/finalizar` or any other skill that merges (hard
  rule 1).
- Before opening a PR: `/verify` (actually run `procyon` on the fixtures the
  PR touches and paste the output), then `/code-review`, and
  `/security-review` for anything touching spec loading, `$ref` resolution or
  file access.
- When implementation contradicts or extends a PRD, update that PRD's
  **Discoveries** section in the same PR.
- When unsure about a product decision, ask the owner (in Portuguese) instead
  of guessing. Technical defaults that follow CONTRIBUTING.md need no question.

## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues (`gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

The five default labels: `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root, created
lazily. See `docs/agents/domain.md`.

## Current state

Updated 2026-10-24. All v0.1 tickets except #13 (Swagger 2.0) and #21
(release) are implemented, each reviewed with `/code-review` before its PR,
and wait for the owner's review and merge. CI cannot run yet: the
repository is private and Actions is not paid; everything was tested on
Linux only.

- Foundation: #22 → #23 (skeleton), #24 → #25 (PRC001). Most other PRs
  stack on #25.
- Siblings on #25: #26 (`--fail-on`), #27 (`x-procyon-public`), #28
  (terminal format), #29 (PRC004), #30 → #31 (PRC002/003/011), #32
  (PRC010), #33 → #34 → #35 (PRC005, PRC009, PRC008), #36 (corpus).
- `integration/v0.1` merges all of those so they can be tested together
  (all green with every rule). #37 (PRC006/007) → #38 → #39 (ignores) →
  #40 → #41 (JSON, `--output`) → #42 (SARIF) → #43 (Markdown) build on it;
  retarget them to `main` once their bases are merged.
- #12 (`$refs`, branch `feat/local-refs`) went through six security review
  rounds; its rules and threat model are in `docs/refs.md`. Its PR is not
  open yet. A CLI `--ref-root` flag still has to be added on top of the
  integration branch.
- After merges: update `testdata/corpus/counts.txt` and `expected.txt`
  (the integration branch has the values with every rule), PRD 0001
  *Discoveries* (deviations are listed in each PR), README example and
  CONTRIBUTING (corpus command).
