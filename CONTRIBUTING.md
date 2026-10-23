# Contributing to Procyon

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).
Security problems in Procyon itself go through [SECURITY.md](SECURITY.md),
never a public issue.

Procyon is a learning project. The rules below exist so that **every line in
`main` has been read, understood and, when it matters, debugged by a human**.
They apply equally to code written by people and by AI assistants.

## The review contract

1. **Small PRs.** Aim for ≤ 300 changed lines (excluding `go.sum`, golden
   files and fixture specs). Larger work is split into several PRs.
2. **Every PR has a review challenge.** The PR description contains a
   `## Review challenge` section with 2–3 questions that can only be answered
   by reading the diff (e.g. "which location does a finding get when the
   schema comes from a `$ref` in another file?", "why does an expired ignore
   produce a finding *and* a note?"). When runtime behavior is the point, it
   may add one **debugger question** answered by setting a breakpoint and
   running.
3. **The reviewer answers in a PR comment.** The author checks the answers. A
   wrong answer means the code or the explanation is unclear, and that gets
   fixed in the PR, not waved through.
4. **Only the owner merges.** Nobody else, and no AI assistant, merges to
   `main`, ever. Merge happens after the challenge is answered correctly and
   CI is green.
5. **Concepts are explained.** When a PR uses a classic data structure or
   algorithm (tree walk, trie, interval matching, hashing, …), the
   description has a `## Concept` section: what it is, the closest LeetCode
   problem, and *why it solves this problem better than the naive approach*.

## Branches and commits

- Never commit directly to `main`. Branch names: `<type>/<short-slug>`, e.g.
  `feat/prc001-missing-auth`, `fix/ref-locations`, `docs/v0.2-prd`.
- [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `refactor:`, `perf:`, `test:`, `docs:`, `chore:`, `ci:`.
  Optional scope: `feat(rules): add PRC004`.
- One logical change per commit. The commit message says *why*, the diff
  says *what*.
- Everything in the repository is in **English**: code, comments, commits,
  docs, PR descriptions.

## Code rules

### Structure
- `cmd/procyon` only parses flags, calls the library and writes formats.
- Everything else lives under `internal/` until a second real consumer needs
  it public. The public library surface is small and documented.
- Rules produce findings. The engine applies public operations, ignores and
  the fail threshold. Formats render a report. None of them reach into
  another's job.

### Errors
- No `panic` on anything that depends on user input or files. Return an
  `error` that says what is wrong, where, and how to fix it when possible.
- Wrap errors with context (`fmt.Errorf("loading %s: %w", path, err)`); the
  CLI prints them as one line.
- A malformed or hostile spec must never crash Procyon or make it read files
  outside what the spec references. Every spec is untrusted input.

### Simplicity
- No abstraction (interface, generic, plugin system, config knob) until a
  second real use case exists.
- Prefer the standard library. Each new module is justified in the PR
  description: what it does, why the stdlib or a few lines of code is not
  enough, and its size.
- Deliberate shortcuts with a known ceiling get a comment:
  `// ponytail: <limit>, <upgrade path>`.

### Rules
- Each rule has a stable ID that is never reused, a title, a severity, an
  OWASP API Security Top 10 category, and a page in `docs/rules/`.
- A rule is deterministic: same spec, same findings, same order.
- Every finding carries a location in the **original** file and a message
  that explains the risk and the fix in plain words.
- Adding or changing a rule comes with fixtures that must trigger it,
  fixtures that must not, and the corpus result in the PR description.

## Tests and CI

- Table tests over small fixture specs in `testdata/`, through the library
  entry point: spec in, findings out. Test what a user sees, not internals.
- Golden files for formats (`go test ./... -update` rewrites them; review the
  diff like code).
- End-to-end CLI tests for exit codes and error messages.
- A corpus of real public specs runs in CI to catch crashes and noise.
- CI runs on every PR, on Linux, macOS and Windows, and must be green before
  merge: `gofmt -l` (empty), `go vet ./...`, `staticcheck ./...`,
  `go test -race ./...`.

## PRDs

- Work starts from a PRD in `docs/prds/`. Read the milestone PRD and the
  vision before starting an issue.
- When implementation reveals something the PRD got wrong or did not know,
  add it to that PRD's **Discoveries** section in the same PR.
