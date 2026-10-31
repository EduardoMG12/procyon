# Running Procyon in CI

Procyon is built to run on every pull request. Its exit code is what fails
the job:

| Code | Meaning |
|---|---|
| `0` | No finding at or above the fail threshold |
| `1` | At least one finding at or above the fail threshold |
| `2` | Procyon could not run (bad arguments, invalid spec, invalid `.procyon.yaml`) |

The threshold is `high` by default. `--fail-on medium` (or `fail-on: medium`
in `.procyon.yaml`) makes medium findings fail the job too. Ignored findings
never fail it.

## `procyon lint` with code scanning and a job summary

`--output` writes other formats next to the terminal output: SARIF for
GitHub code scanning, which shows each finding on the line of the spec it
is about, and Markdown for the job summary. The job needs
`security-events: write` to upload SARIF:

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

Run Procyon before any step that writes credentials into the workspace
(see [how `$refs` are read](refs.md)).

## `procyon test` as a PR comment

This job starts a disposable copy from the repository's compose file, tests
only the operations the PR changes (`--base-spec`), and posts the report,
with its [authorization matrix](testing.md#the-authorization-matrix), as a
comment that later runs update:

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
      - run: go install github.com/EduardoMG12/procyon/cmd/procyon@v0.3.0
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

The tokens here belong to test accounts that exist only in the disposable
copy, so they are not secrets. If your copy needs real credentials to start,
keep those in repository secrets.

Both examples are run by Procyon's own CI
([`ci.yml`](../.github/workflows/ci.yml)), with Procyon built from the
checkout instead of installed, so they cannot rot unnoticed.
