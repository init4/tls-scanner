# TLS / PQC Readiness Scanner

A self-hosted tool for auditing a host's TLS posture: supported protocol
versions, negotiable cipher suites, certificate health, and post-quantum
hybrid key-exchange readiness. Built to point at bare IPs, internal
hostnames, and self-signed/untrusted endpoints -- the kind of thing a normal
browser or HTTP client would refuse to talk to.

- **Backend**: FastAPI (Python), REST API, JSON responses only.
- **Frontend**: React + Vite single-page app, calls the backend over `/api`.
- **Containers**: Podman-first (`podman-compose` or plain `podman play
  kube`, no Docker required), but also works out of the box with plain
  Docker -- `compose.yaml` is the modern Compose Specification filename
  both `podman-compose` and `docker compose` check for by default, and each
  `Dockerfile` is a symlink to the matching `Containerfile`, so there's one
  build definition either way, not two to keep in sync.

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

## Quick start (Docker)

No separate Docker setup to maintain: `compose.yaml` at the repo root is the
one file both `podman-compose` and `docker compose` find by default (don't
add a second compose file under an alternate default name alongside it --
see the comment in `compose.yaml` for why), and `Dockerfile` in each of
`backend/` and `frontend/` is a symlink to the matching `Containerfile`.

```bash
git clone <this repo> tls-scanner && cd tls-scanner
docker compose up --build
# open http://localhost:8080
```

Or without compose:

```bash
docker build -t tls-scanner-backend ./backend
docker build -t tls-scanner-frontend ./frontend
docker network create tls-scanner-net
# --network-alias backend: nginx.conf proxies to http://backend:8000, so the
# backend container needs to answer to that name on the shared network.
docker run -d --name tls-scanner-backend --network tls-scanner-net --network-alias backend tls-scanner-backend
docker run -d --name tls-scanner-frontend --network tls-scanner-net -p 8080:8080 tls-scanner-frontend
# open http://localhost:8080
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
- The one exception is `X25519Kyber768Draft00`, the pre-standard hybrid that
  Chrome and some early PQC rollouts (Cloudflare included) used before the
  final ML-KEM codepoints existed -- OpenSSL 3.5 dropped that identifier
  string outright (it's absent from `openssl list -tls-groups` regardless of
  version), so there's no name the CLI path can ever use for it. That one
  group is instead tested over a raw socket: the scanner sends a TLS 1.3
  ClientHello offering *only* that group's codepoint with an empty
  `key_share` list. RFC 8446 Sec 4.2.8 explicitly allows this specifically to
  elicit a HelloRetryRequest naming the group the server wants a key share
  for next -- since we only offered one group, a server that supports it has
  nothing else to ask for, confirming support without needing to implement
  Kyber's actual key-exchange math at all.
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
    scanner.py   protocol / cipher / certificate (+ chain trust) / PQC-group /
                 legacy-downgrade / DNS CAA / HTTP-header probes
    scoring.py   turns raw probe data into scores, grade, findings
    models.py    pydantic schema for the JSON contract
  Containerfile  builds OpenSSL 3.5 from source, then the FastAPI app
  Dockerfile     symlink -> Containerfile (so plain `docker build` finds it)
frontend/
  src/           React components (dark "security console" UI)
  nginx.conf     serves the built SPA, proxies /api to the backend
  Containerfile  multi-stage: vite build -> nginx
  Dockerfile     symlink -> Containerfile
deploy/
  pod.yaml       plain `podman play kube` deployment (no compose needed)
compose.yaml     one compose file, found by both podman-compose and docker compose
```

## SSLv3 and the other legacy/downgrade checks

Modern OpenSSL (1.1.0+) removed the SSLv3 protocol outright, so there's no
API -- Python `ssl` or OpenSSL CLI -- that can ask it to negotiate SSLv3
anymore. To test it anyway, the scanner hand-builds an SSLv3 ClientHello and
speaks the TLS record layer directly over a raw socket, bypassing the local
TLS stack's protocol support entirely (the same technique tools like
`testssl.sh` use). This also covers three extension-level checks the
`ssl` module has no API for at all, grouped in the UI as "Downgrade &
legacy checks":

- **Secure renegotiation** (RFC 5746) -- its absence means a server that
  allows renegotiation is exposed to the plaintext-injection attack
  (CVE-2009-3555).
- **TLS compression** -- if a server accepts a compressed cipher, it's
  exposed to CRIME-style plaintext recovery.
- **`TLS_FALLBACK_SCSV`** (RFC 7507) -- whether the server actively rejects
  a ClientHello that looks like a client falling back to an older protocol
  version after earlier attempts failed. Only meaningful if the server also
  negotiates a newer version elsewhere in the scan; reported as untestable
  rather than guessed when a TLS 1.0 ClientHello gets no usable response at
  all (common on TLS-1.3-only or WAF-fronted hosts).

All of these report `supported: null` (shown as "untestable" in the UI)
rather than guessing when the probe's ClientHello doesn't get a usable
response -- that's a statement about what could be determined, not a claim
that the check failed.

## Certificate trust, DNS CAA, and HTTP security headers

Three checks that go beyond raw TLS configuration:

- **Chain trust.** Every other probe in this tool connects with certificate
  verification deliberately disabled (`ssl.CERT_NONE`), on purpose -- this
  is a scanner meant to reach self-signed/internal endpoints a normal
  client would refuse. But that design choice used to mean chain trust was
  never checked *at all*, and a host with a flawless protocol/cipher setup
  and a self-signed cert could still earn a top grade. There's now a
  separate probe (`check_chain_trust`) that attempts a REAL, fully-verified
  handshake against the system CA trust store, independent of every other
  probe. If it fails, the overall letter grade is forced to **`T`** (Trust
  Issues) regardless of the underlying numeric score -- the same convention
  Qualys SSL Labs uses. A self-signed or otherwise untrusted chain can no
  longer coexist with a good grade. (The leaf-level inspection -- key size,
  signature algorithm, expiry, self-signed flag -- still happens
  unconditionally either way, same as before; only the grade's relationship
  to trust changed.)
- **DNS CAA** (RFC 8659): a DNS TXT-like record restricting which CAs may
  issue certs for a domain. Checked via a hand-rolled DNS query over UDP
  (Python's stdlib has no API for non-A/AAAA record types) against whatever
  resolver the container itself is configured with -- deliberately not a
  hardcoded public resolver like 8.8.8.8, since that would silently break
  this for internal/split-horizon hostnames. Only queries the exact scanned
  hostname, not the full RFC 8659 parent-domain/CNAME-walk; good enough to
  answer "did this host configure CAA", not a full compliance audit. Not
  applicable to bare-IP targets (CAA is a DNS record, not tied to an IP).
- **HTTP security headers**: a real `GET /` over the established TLS
  connection (no redirect-following), checking for `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and `Permissions-Policy`. Reported as its own score/label
  (like PQC readiness) rather than folded into the main grade, since it's a
  genuinely different security layer -- application hardening, not transport
  crypto. Missing `X-Frame-Options` isn't flagged if `Content-Security-Policy`
  already sets `frame-ancestors`, its modern, more flexible replacement.

## Notes / known limitations

- Legacy protocol probing (TLS 1.0/1.1) depends on the backend's OpenSSL
  still being willing to negotiate them at `SECLEVEL=0`; some hardened
  distros disable this entirely, which will show up as "not supported"
  even on servers that do offer it.
- The cipher-suite candidate lists in `scanner.py` are a representative
  spread, not an exhaustive IANA enumeration -- extend `TLS12_CANDIDATE_CIPHERS`
  if you need suites not covered.
