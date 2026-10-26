# procyon test against crAPI

`.procyon.yaml` and `setup.sh` for running `procyon test` against OWASP
[crAPI](https://github.com/OWASP/crAPI) (Apache-2.0), started from its
public images with its own docker compose file. Used by
`.github/workflows/benchmark.yml`; by hand, from this directory:

```sh
curl -sfLO https://raw.githubusercontent.com/OWASP/crAPI/b5fc307f3e5f875809b095b771108ef342a33724/deploy/docker/docker-compose.yml
curl -sfLO https://raw.githubusercontent.com/OWASP/crAPI/b5fc307f3e5f875809b095b771108ef342a33724/deploy/docker/.env
docker compose -p crapi up -d --wait
./setup.sh                      # signs up alice and bob, adds their vehicles, writes run/.procyon.yaml
cd run && procyon test ../../../corpus/crapi/spec.json --base-url http://127.0.0.1:8888
```

The two accounts are test accounts of a disposable copy, not secrets.
`setup.sh` gives each its vehicle with the VIN and pincode crAPI e-mails
it (read from crAPI's own Mailhog), and declares A's vehicle ID under
`test.ids`: crAPI lists vehicles with a `uuid`, which nothing in the spec
ties to `/vehicle/{vehicleId}/location`. For the rest, `procyon test` has
each account create an object in every collection first. Results are in
[docs/benchmark.md](../../../docs/benchmark.md).
