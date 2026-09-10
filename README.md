# TLS / PQC Readiness Scanner

A self-hosted tool for auditing a host's TLS posture: supported protocol
versions, negotiable cipher suites, certificate health, and post-quantum
hybrid key-exchange readiness. Built to point at bare IPs, internal
hostnames, and self-signed/untrusted endpoints -- the kind of thing a normal
browser or HTTP client would refuse to talk to.

- **Backend**: FastAPI (Python), REST API, JSON responses only.
- **Frontend**: React + Vite single-page app, calls the backend over `/api`.
- **Containers**: Podman-first. Works with `podman-compose` or plain
  `podman play kube`, no Docker required (though the Containerfiles are
  plain OCI and work fine with `docker build`/`docker compose` too).

## Quick start (podman-compose)

```bash
git clone <this repo> tls-scanner && cd tls-scanner
podman-compose up --build
# open http://localhost:8080
```

> **If you hit `short-name "..." did not resolve to an alias and no
> unqualified-search registries are defined`**: some podman setups (rootless
> installs especially) ship without `unqualified-search-registries` set in
> `/etc/containers/registries.conf`, so short image names like `nginx:1.27-alpine`
> have nothing to resolve against. Both Containerfiles here already use
> fully-qualified `docker.io/library/...` image references specifically to
> avoid depending on that config -- if you're still seeing it, you're likely
> building from an older copy; pull the latest Containerfiles. The alternative
> fix, if you'd rather configure it once system-wide, is adding
> `unqualified-search-registries = ["docker.io"]` under `[registries.search]`
> in `/etc/containers/registries.conf`.

## Quick start (plain podman, no compose)

```bash
podman build -t localhost/tls-scanner-backend:latest ./backend
podman build -t localhost/tls-scanner-frontend:latest ./frontend
podman play kube deploy/pod.yaml
# open http://localhost:8080
# tear down: podman play kube --down deploy/pod.yaml
```

## API reference

All responses are JSON. There is no auth layer -- put this behind your own
reverse proxy / VPN if it needs to be reachable outside a trusted network,
since it actively probes whatever host you point it at. Cross-origin access
is disabled by default (`CORS_ALLOW_ORIGINS` is unset); the shipped frontend
doesn't need it since nginx proxies `/api` same-origin, and enabling it on an
unauthenticated scanner would let any website's JS trigger scans and read
the results.

### `GET /api/health`

```bash
curl -s http://localhost:8080/api/health | jq
```

```json
{ "status": "ok", "openssl_version": "OpenSSL 3.5.0 ..." }
```

### `POST /api/scan`

| field     | type   | required | notes                                             |
|-----------|--------|----------|----------------------------------------------------|
| `host`    | string | yes      | hostname or IP; `https://`, a path, or a stray `:port` pasted alongside are stripped automatically |
| `port`    | int    | no       | default `443`                                      |
| `sni`     | string | no       | override the SNI servername; defaults to `host` unless `host` is a bare IP |
| `timeout` | float  | no       | per-probe socket timeout in seconds, default `4.0`  |

Basic scan against a public host:

```bash
curl -s http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "example.com", "port": 443}' | jq
```

Scan a bare internal IP with an untrusted/self-signed cert:

```bash
curl -s http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "10.0.4.12", "port": 8443, "timeout": 3}' | jq
```

Scan an IP that fronts a named vhost, overriding SNI explicitly:

```bash
curl -s http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "10.0.4.12", "port": 443, "sni": "vault.internal"}' | jq
```

Pull just the headline grade and PQC readiness score out of a scan (useful
for a monitoring check or CI gate):

```bash
curl -s http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "example.com"}' \
  | jq '{grade: .scoring.overall_grade, score: .scoring.overall_score, pqc: .scoring.pqc_readiness_label}'
```

```json
{ "grade": "A", "score": 91, "pqc": "Not PQC-ready" }
```

List only the critical/high findings, e.g. for alerting:

```bash
curl -s http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "example.com"}' \
  | jq '[.scoring.findings[] | select(.severity == "critical" or .severity == "high")]'
```

Fail a CI step if the grade drops below B:

```bash
grade=$(curl -s http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "example.com"}' | jq -r '.scoring.overall_grade')

case "$grade" in
  "A+"|"A"|"B") echo "TLS grade OK: $grade" ;;
  *) echo "TLS grade regressed: $grade" >&2; exit 1 ;;
esac
```

## PQC readiness: what "supported" actually means here

The scanner shells out to the local `openssl` CLI with `-groups <name>` to
test hybrid post-quantum key-exchange groups (`X25519MLKEM768` and friends),
because Python's `ssl` module has no portable API for pinning a specific
TLS 1.3 key-share group. This means PQC results are only as good as the
OpenSSL build inside the **backend container**:

- `backend/Containerfile` builds **OpenSSL 3.5.0 from source** specifically
  so the final ML-KEM group names are recognised out of the box.
- If you swap that stage out for your distro's packaged OpenSSL and it's
  older than 3.5, every hybrid-group result will come back as `supported:
  null` with a note that the group name isn't recognised locally -- that's
  a statement about the scanner's own OpenSSL, not about the target server.
  The UI and `pqc_readiness_score` reflect this explicitly rather than
  silently reporting "not supported."
- The headline letter grade (A+ .. F) is **not** affected by PQC results --
  it's graded on classical protocol/cipher/certificate hygiene only. PQC
  readiness is surfaced as its own separate score/badge, since almost no
  server today negotiates a PQC hybrid group and that shouldn't tank an
  otherwise-good TLS configuration's grade.

## Project layout

```
backend/
  app/
    main.py      FastAPI routes, request orchestration (concurrent probes)
    scanner.py   protocol / cipher / certificate / PQC-group probes
    scoring.py   turns raw probe data into scores, grade, findings
    models.py    pydantic schema for the JSON contract
  Containerfile  builds OpenSSL 3.5 from source, then the FastAPI app
frontend/
  src/           React components (dark "security console" UI)
  nginx.conf     serves the built SPA, proxies /api to the backend
  Containerfile  multi-stage: vite build -> nginx
deploy/
  pod.yaml       plain `podman play kube` deployment (no compose needed)
podman-compose.yml
```

## Notes / known limitations

- Certificate chain validation is intentionally disabled everywhere (this
  is a scanner meant to reach untrusted endpoints on purpose). The
  certificate panel reports on the leaf cert's own health (key size, sig
  algorithm, expiry, self-signed) rather than chain trust.
- Legacy protocol probing (TLS 1.0/1.1) depends on the backend's OpenSSL
  still being willing to negotiate them at `SECLEVEL=0`; some hardened
  distros disable this entirely, which will show up as "not supported"
  even on servers that do offer it.
- The cipher-suite candidate lists in `scanner.py` are a representative
  spread, not an exhaustive IANA enumeration -- extend `TLS12_CANDIDATE_CIPHERS`
  if you need suites not covered.
