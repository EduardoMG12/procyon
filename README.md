# Procyon

[![CI](https://github.com/EduardoMG12/procyon/actions/workflows/ci.yml/badge.svg)](https://github.com/EduardoMG12/procyon/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/EduardoMG12/procyon)](https://github.com/EduardoMG12/procyon/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Automatic security QA for APIs, from their OpenAPI spec.** No test cases to
write: Procyon already knows what every API must not allow.

- **`procyon lint`** reads the spec and reports holes in the API's design:
  operations without authentication, secrets in responses, personal data
  shown to anonymous callers, clients that can make themselves admin.
- **`procyon test`** calls a disposable running copy of the API as two test
  accounts and anonymously, and reports what it actually let each one do:
  one user reading another's data, anonymous access, internal errors.

Both run in CI and fail the build before the problem ships. One Go binary,
for an API written in any language: Procyon reads the spec and talks HTTP,
never your source code.

## Why

Your tests check that the API does what it should. Procyon checks that it
can't be misused. Those expectations are the same for every API:

- every operation requires authentication, unless it is public on purpose;
- one user can't reach another user's objects;
- passwords, tokens and secrets never appear in responses;
- clients can't write fields like `role` or `isAdmin`.

It is for developers and small teams without a security team: every finding
says where it is, why it is a risk and how to fix it, in plain words.

## Demo

[vulnapi](internal/vulnapi/README.md) is a small notes API in this
repository, vulnerable on purpose. Its spec looks fine to `lint`:

```text
$ procyon lint internal/vulnapi/openapi.yaml
LOW     PRC008  Unbounded input or output
        internal/vulnapi/openapi.yaml:111:5  GET /notes
…
PASSED  0 high · 0 medium · 5 low · 1 ignored  (fails at: high)
```

Running it is another story. `test` shows, with proof, that user B can read
user A's note:

```text
$ procyon test internal/vulnapi/openapi.yaml --base-url http://127.0.0.1:8080
…
CRITICAL PRC102  Another account reached A's object
        internal/vulnapi/openapi.yaml:145:5  GET /notes/{id}

          143 |     parameters:
          144 |       - $ref: "#/components/parameters/NoteID"
        > 145 |     get:
          146 |       operationId: getNote
          147 |       responses:

        Why:  Test account B called this operation on an object of test account
              A and got 200: any user can read other users' objects by changing
              the ID in the path.
        Fix:  On the server, check that the object belongs to the caller (or
              that the caller may read it) before acting, and answer 404
              otherwise.
        Proof:
          B: GET /notes/1 → 200
            {"id":"1","owner":"alice","title":"Groceries","body":"eggs, milk"}
        More: https://github.com/EduardoMG12/procyon/blob/main/docs/rules/PRC102.md
…
FAILED  8 critical · 2 high · 4 medium · 2 low · 0 ignored  (fails at: high)
```

Its fixed twin (`-fixed`) passes with no findings.

## Install

With Go 1.27.1 or later:

```sh
go install github.com/EduardoMG12/procyon/cmd/procyon@v0.3.0
```

Or download the binary for Linux, macOS or Windows (amd64, arm64) from the
[releases page](https://github.com/EduardoMG12/procyon/releases), and check
it against `SHA256SUMS`:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

## Quick start: `lint`

```sh
procyon lint openapi.yaml
```

That is all: no configuration, no network access. Inputs are OpenAPI 3.0,
3.1 and, in part, 3.2, in YAML or JSON, split across local files or not, and
Swagger 2.0 in one file.

To see findings right away, lint VAmPI, a vulnerable API whose spec is in
this repository:

```text
$ git clone https://github.com/EduardoMG12/procyon && cd procyon
$ procyon lint testdata/corpus/vampi/spec.yml
…
HIGH    PRC005  Response returns a secret
        testdata/corpus/vampi/spec.yml:114:25  GET /users/v1/_debug
…
FAILED  14 high · 0 medium · 10 low · 0 ignored  (fails at: high)
```

Exit code `0` passed, `1` a finding at or above the fail threshold
(`--fail-on`, `high` by default), `2` Procyon could not run.

## Quick start: `test`

`procyon test` needs what a spec cannot say: the credentials of two test
accounts, A and B, that exist in the copy under test. Try it on vulnapi,
from the clone:

```sh
go run ./internal/vulnapi/cmd/vulnapi -addr 127.0.0.1:8080 &
export PROCYON_USER_A_TOKEN=token-alice PROCYON_USER_B_TOKEN=token-bob
procyon test internal/vulnapi/openapi.yaml --base-url http://127.0.0.1:8080
```

On your own API, let Procyon start and tear down the copy with Docker
Compose:

```sh
procyon test openapi.yaml --compose docker-compose.yml --service api --port 8080
```

Give the tokens bare (Procyon adds `Bearer ` when the spec asks for it), or,
for an API that issues tokens, declare its login in `.procyon.yaml`:

```yaml
test:
  accounts:
    a:
      login:
        operation: POST /login
        body: {username: alice, password: "${PROCYON_A_PASSWORD}"}
        token: /session/token
    b:
      login:
        operation: POST /login
        body: {username: bob, password: "${PROCYON_B_PASSWORD}"}
        token: /session/token
```

[docs/testing.md](docs/testing.md) covers server paths, testing only what
a change touches (`--base-spec`), the authorization matrix, and what
`test` cannot find yet.

## What it finds

Each rule has a page with examples, how to fix it, and its known limits.

**`procyon lint`**, from the spec:

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

**`procyon test`**, from a running copy:

| ID | Severity | Catches |
|---|---|---|
| [PRC101](docs/rules/PRC101.md) | critical | Anonymous caller reached an operation that requires authentication |
| [PRC102](docs/rules/PRC102.md) | critical | Another account reached A's object (BOLA) |
| [PRC103](docs/rules/PRC103.md) | medium | Malformed request made the server fail |
| [PRC104](docs/rules/PRC104.md) | low | Server accepted a request the spec forbids |
| [PRC105](docs/rules/PRC105.md) | high | The API's TLS is weak |
| [PRC106](docs/rules/PRC106.md) | high | Public operation returned personal data |
| [PRC107](docs/rules/PRC107.md) | medium | Predictable ID on a public operation |
| [PRC108](docs/rules/PRC108.md) | critical | Another account's list shows A's objects |
| [PRC109](docs/rules/PRC109.md) | medium | A response shows an internal error |

Findings are heuristics over names, shapes and answers, so expect some
noise on large APIs. What neither command finds yet: injection, SSRF, weak
JWTs, missing rate limits, and anything that needs a third account or an
admin role ([details](docs/testing.md#what-it-cannot-find-yet)).

## CI

The exit code fails the job. `--output` writes more formats next to the
terminal output (`terminal`, `json`, `sarif`, `markdown`): here SARIF for
GitHub code scanning and Markdown for the job summary.

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v5
  - uses: actions/setup-go@v6
    with:
      go-version: stable
  - run: go install github.com/EduardoMG12/procyon/cmd/procyon@v0.3.0
  - run: procyon lint openapi.yaml --output sarif=procyon.sarif --output markdown=$GITHUB_STEP_SUMMARY
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: procyon.sarif
```

Add `--fail-on medium` to fail on medium findings too. [docs/ci.md](docs/ci.md)
has a `procyon test` job that posts the report and its authorization
matrix as a PR comment.

## Configuration and ignoring findings

Nothing is required. An optional `.procyon.yaml` sets the flags for the
whole team (`fail-on`, `format`, `output`, `ref-root`) and the `test`
accounts: see [configuration](docs/configuration.md).

A finding that is fine on purpose is ignored **in the spec**, next to what
it excuses, always with a reason, and it stays listed under **Ignored** in
every report. A runtime finding about one field of the response schema can
be ignored for that field only:

```yaml
/shop:
  get:
    x-procyon-public: "The shop's page, shown to every visitor"
    x-procyon-ignore:
      - rule: PRC106
        field: phone
        reason: "The shop's own phone, published on purpose"
        expires: 2027-01-31 # optional
```

See [ignoring a finding](docs/ignoring.md), [how `$refs` are
read](docs/refs.md) and the [JSON format](docs/json-format.md).

## How it is validated

- **vulnapi, on every PR.** CI runs `procyon test --compose` against
  [vulnapi](internal/vulnapi/README.md), which plants a vulnerability for
  every runtime rule but TLS (PRC105), and checks the number of findings of
  each severity; its fixed twin must pass with none.
- **VAmPI and crAPI, every week.** A [benchmark job](.github/workflows/benchmark.yml)
  runs `procyon test` against their public images and fails if a known
  vulnerability is lost. [docs/benchmark.md](docs/benchmark.md) lists, for
  each documented vulnerability there and in Pixi and Juice Shop, what
  Procyon finds and what it misses.
- **Real specs.** `lint` runs in CI over a [corpus](testdata/corpus/README.md)
  of public specs (Petstore, Twilio, USPTO and the vulnerable APIs above),
  with the number of findings per rule pinned, so a noisier rule fails the
  build.

## Safety

`procyon test` changes and deletes data on purpose. Point it only at a
disposable copy whose data does not matter, never at production.

It refuses any base URL that is not a loopback or private address, before
sending a request, and no flag changes that:

```text
$ procyon test openapi.yaml --base-url https://example.com
procyon: --base-url "https://example.com": example.com resolves to 2606:4700:10::ac42:93f3, which is not a loopback or private address; procyon test only calls a disposable copy of your API, never one on the internet
```

`procyon lint` never touches the network, and treats every spec as
untrusted input ([how `$refs` are read](docs/refs.md)).

Procyon is a defensive tool: run it only on APIs you own or are authorized
to test. Security problems in Procyon itself: [SECURITY.md](SECURITY.md).

## Roadmap

| Version | What it does |
|---|---|
| v0.1 — Lint | Reads the spec and reports security problems in the API's design. |
| v0.2 — Runtime tests | Starts a disposable copy with two test accounts, checks that one can't reach the other's data, then tears it down. |
| v0.3 — More runtime checks | Personal data in public answers, predictable IDs on public links, lists that show another account's data, internal errors in responses. |
| **v0.4 — Security QA environment** (next) | Runs continuously against a permanent security-QA environment, with history. |

The [vision](docs/prds/0000-vision.md) and the milestone PRDs in
[docs/prds/](docs/prds/) say what each version is for.

## Contributing

Issues and PRs are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first:
PRs are small, and each one comes with a review challenge. By taking part
you agree to the [code of conduct](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE).
