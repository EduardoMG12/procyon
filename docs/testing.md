# Testing a running copy: `procyon test`

`procyon lint` reads the spec. `procyon test` asks the API itself: it calls
every operation of a running, **disposable** copy as two test accounts (A
and B) and anonymously, and reports what the API let each one do.

```sh
export PROCYON_USER_A_TOKEN=token-of-alice PROCYON_USER_B_TOKEN=token-of-bob
procyon test openapi.yaml --compose docker-compose.yml --service api --port 8080
```

It takes the same flags as `procyon lint` (`--fail-on`, `--format`,
`--output`, `--ref-root`) and the same exit codes.

## What it checks

- **A and B** are two users your environment seeds. Procyon collects A's
  object IDs from A's responses, then checks that:
  - B cannot read, change or delete them (PRC102);
  - a list or search does not hand B A's objects in bulk (PRC108);
  - an anonymous caller cannot use an operation that requires
    authentication (PRC101);
  - a malformed body is refused, not a `5xx` (PRC103) or accepted
    (PRC104);
  - an anonymous answer holds no personal data (PRC106), and is not reached
    by IDs anyone could guess (PRC107);
  - no answer shows a stack trace or a database error (PRC109);
  - on `https`, TLS is sound (PRC105).
- Each finding shows its **proof**: the request, the status and a short
  excerpt of the answer, with tokens, passwords and personal values masked.
- When the test accounts have no objects of their own, they create some
  with the spec's `POST` operations, and a note says so.

It changes and deletes data on purpose, so run it only against a copy whose
data does not matter.

## Where the API runs

- `--compose docker-compose.yml --service api --port 8080` starts a copy
  with `docker compose`, finds the port Docker published for that service,
  tests it, and always tears it down.
- `--base-url http://127.0.0.1:8080` tests a copy you started yourself.

Procyon only ever calls **loopback and private addresses**. A base URL that
resolves to anything else is refused before any request is sent, and there
is no flag to change that:

```text
$ procyon test openapi.yaml --base-url https://example.com
procyon: --base-url "https://example.com": example.com resolves to 2606:4700:10::ac42:93f3, which is not a loopback or private address; procyon test only calls a disposable copy of your API, never one on the internet
```

### Paths

The spec's paths are relative to its first server. When the base URL has no
path, as with `--compose`, the server's path is kept: with
`servers: [{url: /api/v2}]`, `GET /orders` goes to
`http://127.0.0.1:8080/api/v2/orders`. A path in `--base-url`
(`http://127.0.0.1:8080/v2-staging`) replaces it.

## The test accounts

Give the tokens in the environment, bare: Procyon adds `Bearer ` (or what
the operation's security scheme asks for) itself.

```sh
export PROCYON_USER_A_TOKEN=... PROCYON_USER_B_TOKEN=...
```

For an API that issues tokens at login, declare the login in
`.procyon.yaml` instead, with the passwords read from the environment:

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

Form logins, cookie sessions, operations to skip and IDs Procyon cannot
find on its own are in [configuration](configuration.md#logins).

## Only what a change touches

`--base-spec base.yaml` tests only the operations new or changed since that
spec, a shared schema included:

```sh
git show origin/main:openapi.yaml > base.yaml
procyon test openapi.yaml --base-url http://127.0.0.1:8080 --base-spec base.yaml
```

A spec split across files is not compared yet: everything is tested, and a
note says so.

## The authorization matrix

The `markdown` format (`--format markdown`, or `--output markdown=file.md`)
adds a table of each operation and what A, B and an anonymous caller got.
From the [fixed twin of vulnapi](../internal/vulnapi/README.md):

```text
| Operation | A | B (A's objects) | Anonymous |
|---|---|---|---|
| `GET /health` | ✅ 200 | – | 🌐 200 |
| `GET /notes` | ✅ 200 | ✅ 200 | 🚫 401 |
| `GET /notes/{id}` | ✅ 200 | 🚫 404 | 🚫 401 |
| `GET /shop` | ✅ 200 | – | 🌐 200 |
| `DELETE /notes/{id}` | – | 🚫 404 | 🚫 401 |
```

[CI usage](ci.md#procyon-test-as-a-pr-comment) posts it as a PR comment.

## What it cannot find (yet)

- Injection (SQL, NoSQL, commands), SSRF, forged or weak JWTs, missing rate
  limits.
- Mass assignment of fields the spec does not list: Procyon sends only what
  the spec describes.
- Anything that needs more than two accounts or roles (an admin).
- A write whose result no read shows (a password change): that is a note,
  never a pass.

Each rule's page lists its known limits, and the
[benchmark](benchmark.md) shows what it finds in VAmPI and crAPI, and what
it misses.
