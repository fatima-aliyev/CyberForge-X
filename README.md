# CyberForge-X

CyberForge-X is a modular, authorization-gated security assessment framework for
authorized web, API, network, and credential testing. Every outbound request is
scope-checked, rate-limited, budgeted, and non-destructive by policy.

Use it only against systems for which you have explicit written authorization.
The tool requires an exact engagement name from the signed scope file, an
authorization flag, and acceptance of the disclaimer before it sends traffic.

## Safety model

- HTTP methods are allow-listed. `DELETE` is permanently blocked; `PUT` and
  `PATCH` require an explicit write-test flag that is also permitted by scope.
- Form submissions, stored-XSS checks, credential attacks, and authenticated
  attack chains are disabled by default and require both a CLI flag and scope
  permission where applicable.
- Request rate and total volume are capped by the stricter of CLI settings and
  the scope file.
- Every target-facing request is scope-enforced by host/IP/port, including DNS
  resolution checks and redirects. Optional vulnerability-enrichment lookups to
  NVD/EPSS are separate external services and can be disabled with
  `--offline-intel`.
- Cloud metadata addresses are always denied, even if listed in scope.
- Sensitive evidence is redacted in reports. Raw recovered credentials are
  written only to a separate `credentials.json` file for authorized handling.

## Installation

Python 3.10 or newer is required.

```powershell
python -m pip install -e .
python -m pip install -e ".[dev]"
```

Optional integrations for SMB and MongoDB-based checks:

```powershell
python -m pip install -e ".[full]"
```

The SMB and Mongo checks degrade gracefully when their optional dependencies are
not installed.

## Scope

Copy `scope.example.yaml` to `scope.yaml` and replace the example engagement,
authorization reference, hosts, and limits with the signed engagement details.

Validate a scope file without sending traffic:

```powershell
cyberforge validate-scope --scope scope.yaml
```

## Running an assessment

Interactive disclaimer acceptance:

```powershell
cyberforge scan `
  --scope scope.yaml `
  --authorization "Example Client - External Web Assessment" `
  --i-have-authorization `
  --target https://app.example.com
```

Non-interactive runs must provide `--accept-disclaimer` only after the operator
has reviewed and accepted the display notice:

```powershell
cyberforge scan `
  --scope scope.yaml `
  --authorization "Example Client - External Web Assessment" `
  --i-have-authorization `
  --accept-disclaimer `
  --target https://app.example.com `
  --modules recon,intel,web,api,chains `
  --offline-intel
```

The CLI supports the shorthand `cyberforge <scan options>` as well as the
explicit `cyberforge scan <scan options>` form.

### Common options

| Option | Purpose |
| --- | --- |
| `--modules recon,intel,web,api,brute,chains` | Select assessment modules. |
| `--output cyberforge-output` | Base directory for timestamped report runs. |
| `--formats json,md,html` | Report artifacts to generate. |
| `--rate 5 --max-requests 2500` | Effective values are capped by scope. |
| `--proxy URL`, `--insecure` | HTTP proxy and TLS verification override. |
| `--header "Name: value"` | Add an authenticated request header. |
| `--oob-host` | Public callback hostname/IP for RFI/SSRF confirmation. |
| `--max-pages`, `--crawl-depth` | Bound web crawling. |
| `--ports`, `--nmap` | Service discovery range and optional nmap integration. |
| `--offline-intel` | Use the bundled CVE seed data only; disables NVD lookups. |
| `--api-base`, `--auth-a`, `--auth-b` | API surface and BOLA comparison inputs. |
| `--jwt-token`, `--jwt-file` | JWT inputs for offline analysis. |
| `--jwt-test-url`, `--jwt-active-tests` | Gated active JWT acceptance tests. |

### Credential testing

Credential testing requires all of the following:

1. `--allow-credential-attacks`
2. `allow_credential_attacks: true` in the scope file
3. the `brute` module selected
4. explicit targets or `--brute-auto`

The shared attempt budget is bounded, lockout indicators are monitored, and
recovered credentials are isolated in the protected credentials artifact.

```powershell
cyberforge scan `
  --scope scope.yaml `
  --authorization "Example Client - External Web Assessment" `
  --i-have-authorization `
  --accept-disclaimer `
  --target https://app.example.com `
  --modules web,brute `
  --allow-credential-attacks `
  --brute-protocol http-form `
  --brute-auto `
  --brute-max-attempts 10
```

Do not enable credential testing unless account lockout and rate limits have
been coordinated with the system owner.

### Write tests and form submissions

`--allow-form-submissions` and `--enable-write-tests` require
`allow_write_tests: true` in the scope file. Stored XSS testing additionally
requires `--allow-stored-xss` and a form-submission flag.

## Modules

- `recon`: scoped DNS, service/port discovery, HTTP fingerprinting, optional nmap.
- `intel`: technology-to-vulnerability mapping using bundled data and optional NVD/EPSS.
- `web`: bounded crawling, sensitive path discovery, security headers, injection,
  inclusion, DOM source/sink analysis, and gated stored-XSS checks.
- `api`: OpenAPI/Swagger and GraphQL discovery, injected JWT analysis, BOLA
  comparisons, sensitive schema review, and rate-limit observation.
- `brute`: bounded HTTP form, HTTP Basic/Digest, SSH, FTP, and optional SMB
  credential checks.
- `chains`: correlates findings and optionally performs gated authenticated
  follow-up discovery.

## Reports

Each run creates a timestamped directory under the output base containing:

- `report.json`
- `report.md`
- `report.html`
- `credentials.json` when credentials were recovered
- `audit.jsonl`

Main reports mask passwords. Protect and delete `credentials.json` according to
the engagement's data-handling policy.

## Development

```powershell
python -m ruff check cyberforge tests
python -m pytest
```

The test suite covers configuration validation, scope enforcement, authorization
gating, result masking, report escaping, and CLI argument mapping.
