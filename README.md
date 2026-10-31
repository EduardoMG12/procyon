# Procyon

[![CI](https://github.com/EduardoMG12/procyon/actions/workflows/ci.yml/badge.svg)](https://github.com/EduardoMG12/procyon/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Automatic security QA for your API.** Procyon reads your OpenAPI spec and
tells you, in plain words, where your API's design leaves a door open:
operations without authentication, secrets in responses, personal data
exposed to anonymous callers, clients that can make themselves admin. It runs
in CI and fails the build before the problem ships, without you writing a
single test.

> **Status: v0.2.1 released.** `procyon lint` checks the spec; `procyon test`
> checks a running, disposable copy of your API as two users and
> anonymously.

## Why

Your tests check that the API does what it should. Procyon checks that it
can't be misused. The expectations are the same for every API, so Procyon
knows them already:

- every operation requires authentication, unless it is public on purpose;
- one user can't reach another user's objects;
- passwords, tokens and secrets never appear in responses;
- clients can't write fields like `role` or `isAdmin`.

It works for an API written in any language: Procyon reads the spec, never
your source code.

## Usage

Download the binary for your system from the
[releases page](https://github.com/EduardoMG12/procyon/releases) (check it
against `SHA256SUMS`), or install it with Go:

```sh
go install github.com/EduardoMG12/procyon/cmd/procyon@v0.2.1
procyon lint openapi.yaml
```

```text
HIGH    PRC001  Operation has no authentication
        openapi.yaml:7:5  GET /orders

          5 | paths:
          6 |   /orders:
        > 7 |     get:
          8 |       operationId: listOrders
          9 |       responses:

        Why:  Anyone who can reach the API can call this operation, without
              proving who they are.
        Fix:  Add a security requirement to the operation or to the whole spec.
        More: https://github.com/EduardoMG12/procyon/blob/main/docs/rules/PRC001.md

FAILED  1 high · 0 medium · 0 low · 0 ignored  (fails at: high)
```

Exit code `0` passed, `1` a finding at or above the fail threshold, `2`
Procyon could not run. Inputs: OpenAPI 3.0 and 3.1, split across local files
or not, and Swagger 2.0 in one file; YAML or JSON.

| Flag | |
|---|---|
| `--fail-on <severity>` | `critical`, `high` (default), `medium` or `low` |
| `--format <format>` | what to print: `terminal` (default), `json`, `sarif`, `markdown` |
| `--output <format>=<path>` | also write a format to a file; repeatable |
| `--ref-root <dir>` | let `$refs` read anywhere under `dir` (monorepos) |

`fail-on`, `ref-root`, `format` and `output` can also live in a
`.procyon.yaml`. See
[configuration](docs/configuration.md), [ignoring a finding](docs/ignoring.md),
[how `$refs` are read](docs/refs.md) and the [JSON format](docs/json-format.md).

### In GitHub Actions

The job needs `security-events: write` to upload SARIF to code scanning:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v5
  - uses: actions/setup-go@v6
    with:
      go-version: stable
  - run: go install github.com/EduardoMG12/procyon/cmd/procyon@v0.2.1
  - run: procyon lint openapi.yaml --output sarif=procyon.sarif --output markdown=$GITHUB_STEP_SUMMARY
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: procyon.sarif
```

Run Procyon before any step that writes credentials into the workspace
(see [docs/refs.md](docs/refs.md)).

## Testing a running copy: `procyon test` (v0.2, in progress)

`procyon lint` reads the spec. `procyon test` asks the API itself: it starts
a disposable copy from your compose file, calls every operation as two test
accounts (A and B) and anonymously, and reports what the API let each one
do. Then it tears everything down.

```sh
export PROCYON_USER_A_TOKEN=token-of-alice PROCYON_USER_B_TOKEN=token-of-bob
procyon test openapi.yaml --compose docker-compose.yml --service api --port 8080
```

- **A and B** are two users your environment seeds. Procyon collects A's
  object IDs from A's responses and checks that B cannot read, change or
  delete them (PRC102), that anonymous callers cannot use operations that
  require authentication (PRC101), that malformed bodies are refused
  (PRC103, PRC104) and, on `https`, that TLS is sound (PRC105).
- Give the tokens in the environment (bare: Procyon adds `Bearer ` when the
  spec asks for it), or declare a login in
  [`.procyon.yaml`](docs/configuration.md) for APIs that issue tokens.
- `--base-url http://127.0.0.1:8080` tests a copy you started yourself.
  Procyon only ever calls loopback and private addresses: never a system on
  the internet, and there is no flag to change that.
- The spec's paths are relative to its first server. When the base URL
  has no path, as with `--compose`, the server's path is kept: with
  `servers: [{url: /api/v2}]`, `GET /orders` goes to
  `http://127.0.0.1:8080/api/v2/orders`. A path in `--base-url`
  (`http://127.0.0.1:8080/v2-staging`) replaces it.
- `--base-spec base.yaml` tests only the operations new or changed since
  that spec, a shared schema included. A spec split across files is not
  compared yet: everything is tested, and a note says so.
- The `markdown` format adds an **authorization matrix**: each operation,
  and what A, B and an anonymous caller got.

It runs only against a copy you own, and changes and deletes data there on
purpose: never point it at a system whose data matters.

What `procyon test` cannot find (yet): injection (SQL, NoSQL, commands),
SSRF, forged or weak JWTs, missing rate limits, mass assignment of fields
the spec does not list, and anything that needs more than two accounts or
roles (an admin). It cannot confirm a write whose result no read shows (a
password change): that is a note, never a pass. Each rule's page lists its
known limits; [docs/benchmark.md](docs/benchmark.md) shows what it finds in
VAmPI and what it misses.

### In GitHub Actions, as a PR comment

```yaml
name: Procyon runtime tests
on: pull_request
permissions:
  contents: read
  pull-requests: write # the comment
jobs:
  procyon-test:
    runs-on: ubuntu-latest
    env:
      # Accounts your compose file seeds in the disposable copy.
      PROCYON_USER_A_TOKEN: token-alice
      PROCYON_USER_B_TOKEN: token-bob
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v6
        with:
          go-version: stable
      - run: go install github.com/EduardoMG12/procyon/cmd/procyon@v0.2.1
      - name: Test the operations this PR changes
        run: |
          base=()
          if git show "origin/$GITHUB_BASE_REF:openapi.yaml" > base.yaml 2>/dev/null; then
            base=(--base-spec base.yaml)
          fi
          procyon test openapi.yaml --compose docker-compose.yml --service api --port 8080 \
            "${base[@]}" --output markdown=procyon.md
      # A PR from a fork gets a read-only token: the comment fails there.
      - name: Comment, updating the last comment on later runs
        if: always() && hashFiles('procyon.md') != ''
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh pr comment "${{ github.event.pull_request.number }}" --body-file procyon.md --edit-last --create-if-none
```

## Rules

| ID | Severity | Catches |
|---|---|---|
| [PRC001](docs/rules/PRC001.md) | high | Operation has no authentication |
| [PRC002](docs/rules/PRC002.md) | high | Security requirement names an undefined scheme |
| [PRC003](docs/rules/PRC003.md) | medium | API key in the query string, or HTTP Basic |
| [PRC004](docs/rules/PRC004.md) | high | Server URL without TLS |
| [PRC005](docs/rules/PRC005.md) | high | Secret returned in a response |
| [PRC006](docs/rules/PRC006.md) | high | Personal data returned without authentication |
| [PRC007](docs/rules/PRC007.md) | high | Object addressed by ID without authentication |
| [PRC008](docs/rules/PRC008.md) | low | Unbounded input or unpaged list |
| [PRC009](docs/rules/PRC009.md) | medium | Client can write a privileged field (mass assignment) |
| [PRC010](docs/rules/PRC010.md) | medium | Admin operation protected like regular ones |
| [PRC011](docs/rules/PRC011.md) | medium | Deprecated OAuth2 flow |

Runtime rules, found by `procyon test` against a running copy of the API
(v0.2, in progress):

| ID | Severity | Catches |
|---|---|---|
| [PRC101](docs/rules/PRC101.md) | critical | Anonymous caller reached an operation that requires authentication |
| [PRC102](docs/rules/PRC102.md) | critical | Another account reached A's object (BOLA) |
| [PRC103](docs/rules/PRC103.md) | medium | Malformed request made the server fail |
| [PRC104](docs/rules/PRC104.md) | low | Server accepted a request the spec forbids |
| [PRC105](docs/rules/PRC105.md) | high | The API's TLS is weak |

## What it can and cannot see

Procyon reads the spec, so it finds what the spec says: an operation open to
anyone, a password in a response, a writable `role`, an unbounded field. It
cannot see what the server does with a valid request: whose order it
returns, which undocumented field it copies into the record, what it runs.
[docs/benchmark.md](docs/benchmark.md) runs Procyon against four APIs that
are vulnerable on purpose (OWASP crAPI, VAmPI, Pixi, Juice Shop) and shows,
for each documented vulnerability, whether the spec gives it away. Most of
the rest is what v0.2's runtime tests are for.

Findings are heuristics over names and shapes, so expect some noise on
large APIs. Each rule's page lists what it skips on purpose and its known
limits, and a finding you have checked can be [ignored with a
reason](docs/ignoring.md).

## Roadmap

| Version | What it does |
|---|---|
| **v0.1 — Lint** | Reads the spec and reports security problems in the API's design. |
| **v0.2 — Runtime tests** | Starts a disposable copy of your API with test accounts, checks that one user can't reach another's data, then tears it down. Never touches production. |
| **v0.3 — Security QA environment** | Runs continuously against a permanent security-QA environment, with history. |

## Use it responsibly

Procyon is a defensive tool. Run it only on APIs you own or are authorized to
test.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Security problems in Procyon itself:
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
