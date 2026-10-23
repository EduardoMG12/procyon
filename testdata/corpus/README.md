# Corpus

Real specs Procyon is tested against in CI, on top of the small hand-written
fixtures in `testdata/specs/`. Each directory holds one spec (`spec.*`), the
license of the project it comes from (`LICENSE`) and where and when it was
taken (`SOURCE`).

| Directory | API | License | Why it is here |
|---|---|---|---|
| `petstore` | Swagger Petstore | Apache-2.0 | The best-known example API |
| `uspto` | US Patent and Trademark Office data set API | Apache-2.0 | A small real government API |
| `twilio-oauth`, `twilio-chat`, `twilio-routes` | Twilio | MIT | Generated specs from a large vendor |
| `crapi` | OWASP crAPI | Apache-2.0 | Vulnerable on purpose |
| `vampi` | VAmPI | MIT | Vulnerable on purpose |

## The two tests

**`TestCorpus`** lints every spec. None may fail to load, and the number of
findings per spec and rule is pinned in `counts.txt`. A change that makes a
rule noisier or quieter fails the test. If the change is intended, update
the file and explain the difference in the PR:

```sh
go test ./internal/lint -run TestCorpus -update-corpus
git diff testdata/corpus/counts.txt
```

**`TestKnownBadSpecs`** checks the answer key in `expected.txt`: findings
Procyon must report on the APIs that are vulnerable on purpose. A missing one
is a false negative and fails the test. When a rule lands, add the known
problems it must find there, each with a comment saying what the problem is.
Only problems visible in the spec belong there; problems that live in the
APIs' code are for runtime tests (v0.2).

## Adding a spec

Only specs whose license allows redistribution (Apache-2.0, MIT, BSD, CC-BY,
…). Never a GPL-licensed one: copying it into this Apache-2.0 repository would
bring the GPL's terms with it. Keep them small (under ~200 KB); a huge spec
belongs in an ad-hoc local test, not in the repository.
