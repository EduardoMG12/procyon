# procyon test against VAmPI

`.procyon.yaml` for running `procyon test` against
[VAmPI](https://github.com/erev0s/VAmPI) (MIT), started from its public image
with `vulnerable=1`. It is used by `.github/workflows/benchmark.yml`; run it
by hand from this directory:

```sh
docker run -d --name vampi -e vulnerable=1 -p 127.0.0.1:5000:5000 erev0s/vampi:latest
curl -s http://127.0.0.1:5000/createdb   # seeds name1/pass1, name2/pass2, admin
procyon test ../../corpus/vampi/spec.yml --base-url http://127.0.0.1:5000
```

The seeded users are VAmPI's own test accounts, not secrets. `GET /createdb`
is skipped: it reseeds the database, which would invalidate the IDs a run
collected. Results are in [docs/benchmark.md](../../../docs/benchmark.md).
