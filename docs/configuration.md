# Configuration

Procyon needs no configuration. Everything below is optional.

## Fail threshold

`--fail-on <severity>` sets the lowest severity that fails the run (exit code
`1`). Severities, from most to least serious: `critical`, `high`, `medium`,
`low`. The default is `high`.

```sh
procyon lint openapi.yaml --fail-on medium
```

## `.procyon.yaml`

An optional `.procyon.yaml` in the directory you run Procyon from sets the same
options for the whole team:

```yaml
fail-on: medium
ref-root: .
format: terminal
output:
  - sarif=procyon.sarif
  - markdown=summary.md
```

Flags always win over the file. One `--output` flag replaces the file's whole
`output` list, so a local run never writes files you did not ask for.

| Key | Flag | Meaning |
|---|---|---|
| `fail-on` | `--fail-on` | The lowest severity that fails the run |
| `ref-root` | `--ref-root` | A directory `$refs` may read anywhere under, instead of only the spec's own directory: for monorepos whose specs share files from a sibling folder. A relative path counts from the directory Procyon runs in. See [how `$refs` are read](refs.md). |
| `format` | `--format` | What to print: `terminal` (default), `json`, `sarif` or `markdown` |
| `output` | `--output` | A list of `format=path`: other formats to write to files |
| `test.accounts.a.login`, `test.accounts.b.login` | | For `procyon test`: how test account A or B logs in, when `PROCYON_USER_A_TOKEN` / `PROCYON_USER_B_TOKEN` is not set. `operation` (`POST /login`, as in the spec), `body` (sent as JSON; `${PROCYON_…}` reads an environment variable, so no password is written in the file; only names starting with `PROCYON_` can be read, so a changed config cannot send CI's other secrets to the target) or `form` (the same, sent form-encoded), and `token` (a JSON pointer to the token in the response, such as `/token` or `/session/token`) or `cookie` (the name of the cookie the response sets with the token). See [logins](#logins) |
| `test.skip` | | For `procyon test`: operations never called, by anyone (`["GET /createdb"]`): a "read" that resets the database would spoil the run |
| `test.ids` | | For `procyon test`: values of test account A's objects by path parameter name (`orderId: ["42"]`): used when A's responses show none, or none Procyon can tell is A's |

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

### Logins

A login sends `body` as JSON, or `form` form-encoded, and reads the token
from the JSON answer at `token`, or from the cookie named `cookie`. Pick
one of each. Procyon then sends the token the way each operation's
security scheme says: a bearer header, or an API key in a header, query or
cookie. With a cookie login, the spec should say the session is a cookie
(`type: apiKey, in: cookie, name: sid`); with no security scheme, the token
is never sent.

```yaml
test:
  accounts:
    a:
      login:
        operation: POST /token     # FastAPI's OAuth2 password form
        form: {username: alice, password: "${PROCYON_A_PASSWORD}"}
        token: /access_token
    b:
      login:
        operation: POST /session   # the token comes back as Set-Cookie: sid=...
        body: {username: bob, password: "${PROCYON_B_PASSWORD}"}
        cookie: sid
```

A cookie login may answer `2xx` or a redirect (`303` to the start page is
common); the cookie is read from that answer, and the redirect is not
followed. The token and the passwords read from `${PROCYON_…}` are masked
in evidence, like tokens from the environment.

### When `test.ids` is needed

Procyon finds the IDs of A's objects by reading A's responses first: `GET
/notes` shows `{"id": "1"}`, which fills `GET /notes/{id}`. Declare
`test.ids` only when the report has one of these notes:

- **`GET /orders/{orderId} not tested: no value for {orderId} in A's
  responses`**. Nothing A can read shows the value: there is no `GET` on
  the collection (`GET /orders`), or its objects have no `id` and no
  response has a field named like the parameter (`{"number": "42"}` for
  `{orderId}`), or the object sits under a parent no list shows
  (`/shops/{shopId}/orders/{orderId}`), or A's lists are empty and the
  spec has no `POST` to create one.
- **`not tested as B: every user is shown this object's ID and nothing
  marks it as A's`**. The list shows every user's objects (a public list of
  books), and no value in them marks A: no `GET /me` whose username or ID
  appears in A's object. B reading such an object proves nothing, so B is
  not tested on it.

Give the value of an object A owns in the environment, by the path
parameter's name (`order_id`, `orderId` and `order-id` are the same):

```yaml
test:
  ids:
    orderId: ["42"]
```

A declared value counts as A's own, so B is tested on it.

An unknown key is an error, so a typo such as `fail_on` never goes unnoticed.

The file holds **how** Procyon runs, never **what it ignores**. Ignores live in
the spec, on the operation they excuse, with a written reason, so the
exception sits next to what it describes and is reviewed with it.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above the fail threshold |
| `1` | At least one finding at or above the fail threshold |
| `2` | Procyon could not run: bad arguments, unreadable or invalid spec, invalid `.procyon.yaml` |
