#!/usr/bin/env bash
#
# Author: Aria Jahangiri Far - https://github.com/MrAriaNet
#
# Unified security remediation for:
#   - cPanel/WHM CVE-2026-41940 (auth bypass) - align with vendor + common provider hardening
#   - Linux kernel CVE-2026-31431 ("Copy Fail") - algif_aead mitigation per https://copy.fail/
#
# References:
#   https://support.cpanel.net/hc/en-us/articles/40073787579671-Security-CVE-2026-41940-cPanel-WHM-WP2-Security-Update-04-28-2026
#   https://copy.fail/#copy-fail
#
# Usage:
#   ./security-remediation.sh [--check-only] [--fix-cpanel] [--fix-kernel] [--fix-csf|--csf-strip-panel-ports]
#                             [--purge-cpanel-sessions] [--fix-all] [--dry-run] [--non-interactive]
#                             [--list-domains] [--domain-list-output=FILE] [--remove-service-subdomains]
#                             [--extra-hardening] [--extra-hardening-csf]
#
# CSF: --fix-csf merges panel ports into TCP_IN (restore access). --csf-strip-panel-ports removes the
# emergency lockdown port set from TCP_IN (opposite operation). Do not use both CSF modes together.
#
# Defaults: if no --fix-* flags, runs assessment only (same as --check-only).
#

set -u

readonly SCRIPT_NAME="$(basename "$0")"
readonly CPANEL_BIN="/usr/local/cpanel/cpanel"
readonly MODPROBE_SNIPPET="/etc/modprobe.d/disable-algif_aead-CVE-2026-31431.conf"
# Re-add these after a patch if they were dropped during incident firewall tightenings.
readonly CSF_CPANEL_PORTS=(2083 2087 2095 2096)
# Strip these from TCP_IN for temporary panel/WHM lockdown (matches common CSF playbooks).
readonly CSF_STRIP_PORTS=(2077 2078 2079 2080 2082 2083 2086 2087 2095 2096)
readonly CSF_CONF="/etc/csf/csf.conf"

# Minimum fully patched cPanel & WHM builds per release line (April 28 2026 advisory).
# WP Squared: use vendor guidance (e.g. 136.1.7); this script focuses on standard cpanel -V output.
declare -A MIN_SAFE_CPANEL=(
  ["11.86.0"]="11.86.0.41"
  ["11.110.0"]="11.110.0.97"
  ["11.118.0"]="11.118.0.63"
  ["11.126.0"]="11.126.0.54"
  ["11.130.0"]="11.130.0.19"
  ["11.132.0"]="11.132.0.29"
  ["11.134.0"]="11.134.0.20"
  ["11.136.0"]="11.136.0.5"
)

DRY_RUN=0
CHECK_ONLY=1
FIX_CPANEL=0
FIX_KERNEL=0
FIX_CSF=0
FIX_CSF_STRIP=0
PURGE_CPANEL_SESSIONS=0
LIST_DOMAINS=0
DOMAIN_LIST_FILE=""
REMOVE_SERVICE_SUBDOMAINS=0
EXTRA_HARDENING=0
EXTRA_HARDEN_CSF=0
NON_INTERACTIVE=0

log() { printf '[%s] %s\n' "$SCRIPT_NAME" "$*"; }
die() { log "ERROR: $*"; exit 1; }

ver_lt() {
  local a="$1" b="$2"
  [[ "$a" == "$b" ]] && return 1
  [[ "$(printf '%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Run as root (this script changes system configuration)."
}

prompt_yes() {
  local msg="$1"
  [[ "$NON_INTERACTIVE" -eq 1 ]] && return 0
  read -r -p "$msg [y/N] " x || return 1
  [[ "${x,,}" == "y" || "${x,,}" == "yes" ]]
}

get_cpanel_version() {
  if [[ ! -x "$CPANEL_BIN" ]]; then
    echo ""
    return 1
  fi
  "$CPANEL_BIN" -V 2>/dev/null | head -1 | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

cpanel_branch_key() {
  # "11.110.0.97" -> "11.110.0"
  local v="$1"
  echo "$v" | awk -F. 'NF>=4 {print $1"."$2"."$3}'
}

assess_cpanel_cve_2026_41940() {
  local ver
  ver="$(get_cpanel_version)"
  if [[ -z "$ver" ]]; then
    log "cPanel not detected (${CPANEL_BIN} missing or not executable)."
    return 0
  fi
  log "cPanel version reported: $ver"
  local key
  key="$(cpanel_branch_key "$ver")"
  local min="${MIN_SAFE_CPANEL[$key]:-}"
  if [[ -z "$min" ]]; then
    log "WARN: Release line '${key:-unknown}' not in built-in patch table."
    log "      Compare your build to the vendor list and run /scripts/upcp --force if behind."
    log "      https://support.cpanel.net/hc/en-us/articles/40073787579671-Security-CVE-2026-41940-cPanel-WHM-WP2-Security-Update-04-28-2026"
    return 2
  fi
  if ver_lt "$ver" "$min"; then
    log "STATUS: Potentially VULNERABLE to CVE-2026-41940 (need >= $min for line $key, have $ver)."
    return 1
  fi
  log "STATUS: cPanel build meets minimum patched level for line $key (>= $min)."
  return 0
}

fix_cpanel_update() {
  [[ -x "$CPANEL_BIN" ]] || { log "Skipping cPanel update: cPanel not installed."; return 0; }
  local st=0
  assess_cpanel_cve_2026_41940 || st=$?
  if [[ "$st" -eq 0 ]]; then
    log "cPanel update not required based on version check."
    return 0
  fi
  if [[ "$st" -eq 2 ]]; then
    log "Release line not in the built-in table - confirm patched level in the vendor article (WP Squared, pinned tiers, EOL branches)."
  fi

  log "Recommended (vendor): /scripts/upcp --force then hard restart cpsrvd."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would run: /scripts/upcp --force"
    log "[dry-run] Would run: /scripts/restartsrv_cpsrvd --hard"
    log "[dry-run] Would flush /var/cpanel/sessions/{raw,cache,preauth} and run /scripts/restartsrv_cpsrvd --hard again"
    return 0
  fi
  prompt_yes "Run /scripts/upcp --force now? This may take a long time." || { log "Skipped cPanel update."; return 0; }

  if [[ ! -x /scripts/upcp ]]; then
    die "/scripts/upcp not found - is this a full cPanel & WHM server?"
  fi
  /scripts/upcp --force
  log "Restarting cPanel services (vendor guidance)..."
  if [[ -x /scripts/restartsrv_cpsrvd ]]; then
    /scripts/restartsrv_cpsrvd --hard
  else
    log "WARN: /scripts/restartsrv_cpsrvd not found; restart cpsrvd manually."
  fi
  log "Verify: $CPANEL_BIN -V"

  log "Flushing hot session caches (raw, cache, preauth) and restarting cpsrvd…"
  cpanel_flush_hot_sessions
}

# Clear pre-auth and cached session files (recommended after auth-related CVE patching).
cpanel_flush_hot_sessions() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would clear /var/cpanel/sessions/{raw,cache,preauth} and run /scripts/restartsrv_cpsrvd --hard"
    return 0
  fi
  if [[ ! -x "$CPANEL_BIN" ]]; then
    log "Skipping session flush: cPanel not installed."
    return 0
  fi
  log "Clearing hot session directories…"
  local d
  for d in /var/cpanel/sessions/raw /var/cpanel/sessions/cache /var/cpanel/sessions/preauth; do
    if [[ -d "$d" ]]; then
      find "$d" -mindepth 1 -maxdepth 1 -exec rm -f {} + 2>/dev/null || true
    fi
  done
  if [[ -x /scripts/restartsrv_cpsrvd ]]; then
    /scripts/restartsrv_cpsrvd --hard
  else
    log "WARN: /scripts/restartsrv_cpsrvd not found after session flush."
  fi
  log "Session flush complete."
}

# --- All domains (for listing / proxy & service subdomain removal) -----------------

cpanel_domain_rows_from_userdomains() {
  local f="/etc/userdomains"
  [[ -f "$f" ]] || return 1
  awk -F':' '!/^#/ && NF>=2 {
    dom = $1
    gsub(/^[ \t]+|[ \t]+$/, "", dom)
    user = $2
    for (i = 3; i <= NF; i++) user = user ":" $i
    gsub(/^[ \t]+|[ \t]+$/, "", user)
    if (dom != "" && user != "" && dom != "*")
      print user "\t" dom
  }' "$f" | sort -u
}

cpanel_emit_domain_list() {
  local rows header='user	domain'
  rows="$(cpanel_domain_rows_from_userdomains)" || {
    log "Could not read /etc/userdomains (is this cPanel?)."
    return 1
  }
  printf '%s\n%s\n' "$header" "$rows"
  log "Total domain rows: $(printf '%s\n' "$rows" | wc -l) (from /etc/userdomains)"
  if [[ -n "$DOMAIN_LIST_FILE" ]]; then
    printf '%s\n%s\n' "$header" "$rows" >"$DOMAIN_LIST_FILE"
    log "Also wrote list to $DOMAIN_LIST_FILE"
  fi
}

# Strip hostname-style access on 80/443 (cpanel./webmail./whm.*) and matching service records.
# Uses /scripts/proxydomains (see cPanel KB: proxy / HTTP layer), then /scripts/servicedomains remove.
cpanel_remove_proxy_and_service_subdomains() {
  local px="/scripts/proxydomains"
  local sd="/scripts/servicedomains"
  if [[ ! -x "$px" && ! -x "$sd" ]]; then
    die "Neither /scripts/proxydomains nor /scripts/servicedomains is executable - cannot remove service subdomains."
  fi

  local rows
  rows="$(cpanel_domain_rows_from_userdomains)" || die "Could not read /etc/userdomains."
  [[ -n "$rows" ]] || die "No domains found in /etc/userdomains."

  local n
  n="$(printf '%s\n' "$rows" | grep -c . || true)"
  log "Prepared $n user/domain pairs from /etc/userdomains."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would run per pair (where scripts exist):"
    [[ -x "$px" ]] && log "[dry-run]   $px --user=USER --domain=DOMAIN remove"
    [[ -x "$sd" ]] && log "[dry-run]   $sd remove --user=USER --domain=DOMAIN"
    return 0
  fi
  prompt_yes "Remove proxy/service subdomains for all listed domains? This tears down cpanel./webmail./whm.* style names on 80/443 for those accounts (see cPanel documentation)." || {
    log "Skipped service subdomain removal."
    return 0
  }

  local user dom
  while IFS=$'\t' read -r user dom; do
    [[ -z "$user" || -z "$dom" ]] && continue
    if [[ -x "$px" ]] && ! "$px" --user="$user" --domain="$dom" remove && ! "$px" remove --user="$user" --domain="$dom"; then
      log "WARN: proxydomains remove failed for user=$user domain=$dom"
    fi
    if [[ -x "$sd" ]] && ! "$sd" remove --user="$user" --domain="$dom"; then
      log "WARN: servicedomains remove failed for user=$user domain=$dom"
    fi
  done <<<"$rows"

  log "Finished proxy/servicedomains passes (logged failures above). Run /scripts/updateuserdomains if DNS still looks wrong."
}

csf_parse_tcp_in_csv() {
  grep -E '^TCP_IN[[:space:]]*=' "$CSF_CONF" 2>/dev/null | head -1 | sed 's/.*=//;s/"//g;s/'"'"'//g' | tr -d '[:space:]'
}

# Args: merge|strip  /path/to/csf.conf  port [port ...]
csf_tcp_in_edit_python() {
  python3 - "$@" <<'PY'
import re, sys
op, path = sys.argv[1], sys.argv[2]
ports = sys.argv[3:]
with open(path, encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()
out = []
pat = re.compile(r'^(\s*TCP_IN\s*=\s*")([^"]*)("\s*)$')
for line in lines:
    m = pat.match(line.rstrip("\n"))
    if not m:
        out.append(line)
        continue
    q1, body, q3 = m.group(1), m.group(2), m.group(3)
    parts = [p.strip() for p in body.split(",") if p.strip()]
    if op == "merge":
        present = set(parts)
        for p in ports:
            if p not in present:
                parts.append(p)
                present.add(p)
    elif op == "strip":
        drop = set(ports)
        parts = [p for p in parts if p not in drop]
    else:
        raise SystemExit("bad op")
    out.append(q1 + ",".join(parts) + q3 + "\n")
with open(path, "w", encoding="utf-8", newline="") as f:
    f.writelines(out)
PY
}

csf_ensure_cpanel_ports() {
  if [[ ! -f "$CSF_CONF" ]]; then
    log "CSF not found at $CSF_CONF - skipping."
    return 0
  fi
  if ! command -v csf >/dev/null 2>&1; then
    log "csf not in PATH - skipping."
    return 0
  fi

  local ports_csv missing=() p
  ports_csv="$(csf_parse_tcp_in_csv)"
  if [[ -z "$ports_csv" ]]; then
    log "Could not parse TCP_IN - review $CSF_CONF manually."
    return 2
  fi

  for p in "${CSF_CPANEL_PORTS[@]}"; do
    [[ ",${ports_csv}," == *",${p},""* ]] || missing+=("$p")
  done
  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "CSF TCP_IN already includes standard cPanel/WHM ports (${CSF_CPANEL_PORTS[*]})."
    return 0
  fi
  log "TCP_IN missing: ${missing[*]}"

  if [[ "$FIX_CSF" -eq 0 ]]; then
    log "STATUS: Add those ports to TCP_IN in $CSF_CONF then: csf -r"
    return 1
  fi

  log "Merging missing ports into CSF TCP_IN."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would merge ports into TCP_IN and run: csf -r"
    return 0
  fi
  prompt_yes "Modify CSF TCP_IN to include ${CSF_CPANEL_PORTS[*]}?" || { log "Skipped CSF change."; return 0; }

  command -v python3 >/dev/null 2>&1 || die "python3 is required to edit $CSF_CONF safely."

  local backup="${CSF_CONF}.bak.${SCRIPT_NAME}.$(date +%Y%m%d%H%M%S)"
  cp -a "$CSF_CONF" "$backup"
  log "Backup: $backup"

  csf_tcp_in_edit_python merge "$CSF_CONF" "${CSF_CPANEL_PORTS[@]}"
  csf -r
  log "CSF reloaded."
}

csf_strip_panel_ports() {
  if [[ ! -f "$CSF_CONF" ]]; then
    log "CSF not found at $CSF_CONF - skipping strip."
    return 0
  fi
  if ! command -v csf >/dev/null 2>&1; then
    log "csf not in PATH - skipping strip."
    return 0
  fi

  log "Removing from TCP_IN: ${CSF_STRIP_PORTS[*]}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would edit $CSF_CONF and run: csf -r"
    return 0
  fi
  prompt_yes "Drop panel/WHM ports from TCP_IN (CSF will block those inbound)?" || { log "Skipped CSF strip."; return 0; }

  command -v python3 >/dev/null 2>&1 || die "python3 is required to edit $CSF_CONF."

  local backup="${CSF_CONF}.bak.${SCRIPT_NAME}.strip.$(date +%Y%m%d%H%M%S)"
  cp -a "$CSF_CONF" "$backup"
  log "Backup: $backup"

  csf_tcp_in_edit_python strip "$CSF_CONF" "${CSF_STRIP_PORTS[@]}"
  csf -r
  log "CSF reloaded."
}

kernel_alg_mitigation_present() {
  [[ -f "$MODPROBE_SNIPPET" ]] || return 1
  grep -qs 'install[[:space:]]\+algif_aead[[:space:]]\+/bin/false' "$MODPROBE_SNIPPET"
}

assess_kernel_cve_2026_31431() {
  log "Kernel: $(uname -r)"
  if kernel_alg_mitigation_present; then
    log "STATUS: algif_aead blacklist present ($MODPROBE_SNIPPET)."
  else
    log "STATUS: algif_aead module mitigation NOT configured (see CVE-2026-31431)."
  fi
  if lsmod 2>/dev/null | grep -q '^algif_aead'; then
    log "STATUS: algif_aead is LOADED in the running kernel."
    return 1
  fi
  log "STATUS: algif_aead not loaded (good for interim hardening before kernel package update)."
  return 0
}

fix_kernel_alg_mitigation() {
  assess_kernel_cve_2026_31431 || true

  if kernel_alg_mitigation_present && ! lsmod 2>/dev/null | grep -q '^algif_aead'; then
    log "Kernel mitigation already applied."
    return 0
  fi

  log "Permanent fix: update kernel from your vendor to a build containing mainline commit a664bf3d603d"
  log "(see https://copy.fail/#copy-fail). Interim workaround: disable algif_aead."

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would write $MODPROBE_SNIPPET and run: modprobe -r algif_aead"
    return 0
  fi
  prompt_yes "Apply modprobe blacklist for algif_aead and unload module now?" || { log "Skipped kernel mitigation."; return 0; }

  umask 022
  cat >"$MODPROBE_SNIPPET" <<'EOF'
# CVE-2026-31431 ("Copy Fail") interim mitigation - disable AF_ALG AEAD socket module.
# Remove after kernel package includes fix (mainline commit a664bf3d603d).
install algif_aead /bin/false
EOF
  log "Wrote $MODPROBE_SNIPPET"

  if modprobe -r algif_aead 2>/dev/null; then
    log "Unloaded algif_aead."
  else
    log "Note: algif_aead could not be unloaded (may be in use or built-in). Reboot may be required."
  fi
  log "After vendor kernel update, remove this file if you no longer need the workaround."
}

# --- Optional hardening (rpcbind, WHM tweaks, compilers, CSF) ------------------------------

harden_rpcbind_optional() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would stop/disable rpcbind via systemctl."
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -qE '^rpcbind\.service'; then
      systemctl stop rpcbind 2>/dev/null || true
      systemctl disable rpcbind 2>/dev/null || true
      log "rpcbind stopped and disabled."
    else
      log "rpcbind.service not installed - skipped."
    fi
  else
    log "systemctl not available - rpcbind step skipped."
  fi
}

disable_whm_terminal_ui_file() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would touch /var/cpanel/disable_whm_terminal_ui"
    return 0
  fi
  touch /var/cpanel/disable_whm_terminal_ui 2>/dev/null || log "WARN: could not touch disable_whm_terminal_ui."
  log "WHM Terminal UI flag set (/var/cpanel/disable_whm_terminal_ui)."
}

run_whm_tweak_setting() {
  local key="$1" val="$2"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] whmapi1 set_tweaksetting key=$key value=$val"
    return 0
  fi
  if ! command -v whmapi1 >/dev/null 2>&1; then
    log "WARN: whmapi1 not found - cannot set tweak $key."
    return 0
  fi
  if ! whmapi1 set_tweaksetting "key=$key" "value=$val" >/dev/null 2>&1; then
    log "WARN: set_tweaksetting key=$key value=$val returned non-zero - check WHM on this version."
  fi
}

apply_extra_hardening_whm_tweaks() {
  log "Applying WHM tweak settings (password/UI/referrer/cookie/proxy subdomains)…"
  run_whm_tweak_setting resetpass 0
  run_whm_tweak_setting resetpass_sub 0
  run_whm_tweak_setting referrerblanksafety 1
  run_whm_tweak_setting cgihidepass 1
  run_whm_tweak_setting referrersafety 1
  run_whm_tweak_setting allow_login_autocomplete 0
  run_whm_tweak_setting cookieipvalidation strict
  run_whm_tweak_setting proxysubdomains 0
}

run_compilers_off() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] /scripts/compilers off"
    return 0
  fi
  if [[ ! -x /scripts/compilers ]]; then
    log "WARN: /scripts/compilers not found - skipped."
    return 0
  fi
  /scripts/compilers off
  log "Compilers script set to off."
}

apply_extra_hardening_bundle() {
  log "=== Extra hardening: OS + WHM + compilers (recommended checklist) ==="
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would apply rpcbind disable, WHM terminal disable, WHM tweaks, compilers off."
    return 0
  fi
  prompt_yes "Apply extra hardening (rpcbind, disable WHM Terminal UI, WHM security tweaks, compilers off)?" || {
    log "Skipped extra hardening."
    return 0
  }
  harden_rpcbind_optional
  disable_whm_terminal_ui_file
  apply_extra_hardening_whm_tweaks
  run_compilers_off
  log "Extra hardening steps finished."
}

# Aggressive CSF profile: REWRITES TCP_IN to a fixed port list (drops custom/WHM ports unless listed).
# Conflicts with --fix-csf - choose one policy per run.
apply_extra_hardening_csf_saeed() {
  local cf="$CSF_CONF"
  if [[ ! -f "$cf" ]]; then
    log "CSF config missing - skipping aggressive CSF step."
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] Would backup $cf and apply sysctl-style CSF tweaks + fixed TCP_IN + csf -r / csf -ra."
    return 0
  fi
  prompt_yes "DESTRUCTIVE: Rewrite CSF TCP_IN and several CSF options per checklist (may drop ports like 2087/2222 if not in list). Continue?" || {
    log "Skipped aggressive CSF."
    return 0
  }

  local backup
  backup="${cf}.bak.${SCRIPT_NAME}.harden.$(date +%Y%m%d%H%M%S)"
  cp -a "$cf" "$backup"
  log "Backup: $backup"

  sed -i \
    -e 's/TESTING = "1"/TESTING = "0"/g' \
    -e 's/RESTRICT_SYSLOG = "0"/RESTRICT_SYSLOG = "3"/g' \
    -e 's/SYSLOG_CHECK = "0"/SYSLOG_CHECK = "1200"/g' \
    -e 's/SYSLOG = "0"/SYSLOG = "1"/g' \
    -e 's/PT_LIMIT = "60"/PT_LIMIT = "0"/g' \
    -e 's/DROP_ONLYRES = "1"/DROP_ONLYRES = "0"/g' \
    -e 's/^TCP_IN = ".*"/TCP_IN = "20,21,25,53,80,110,143,443,465,587,853,993,995,2082,2083"/g' \
    "$cf"

  # Append passive/ephemeral range to the TCP_IN line when missing.
  if ! grep -q '49152:65534' "$cf"; then
    sed -Ei 's/^(TCP_IN = )"([^"]+)"/\1"\2,49152:65534"/' "$cf"
  fi

  log "Updated CSF config (showing TCP_IN line):"
  grep -E '^TCP_IN[[:space:]]*=' "$cf" | head -1 || true

  if command -v csf >/dev/null 2>&1; then
    csf -r
    csf -ra
    log "Ran csf -r and csf -ra."
  else
    log "WARN: csf not in PATH - reload CSF manually."
  fi
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

  --check-only       Assessment only (default if no fix flags)
  --fix-cpanel       Run /scripts/upcp --force and hard restart cpsrvd if version is below patched floor
  --fix-kernel       Write modprobe drop-in for algif_aead and attempt rmmod
  --fix-csf              Merge cPanel ports (${CSF_CPANEL_PORTS[*]}) into CSF TCP_IN and csf -r
  --csf-strip-panel-ports  Remove lockdown ports (${CSF_STRIP_PORTS[*]}) from TCP_IN; conflicts with --fix-csf
  --purge-cpanel-sessions  Clear raw/cache/preauth under /var/cpanel/sessions and hard-restart cpsrvd
  --list-domains           Print every domain line from /etc/userdomains (tab: user, domain)
  --domain-list-output=FILE  Optional file path for the same list when using --list-domains
  --remove-service-subdomains  Run /scripts/proxydomains remove + /scripts/servicedomains remove per domain (no 80/443 proxy hostnames)
  --fix-all              cPanel + kernel + merge CSF ports (does not include strip, purge, domains)
  --extra-hardening      rpcbind off, disable WHM Terminal UI, WHM security tweaks, /scripts/compilers off
  --extra-hardening-csf  Aggressive CSF edits + fixed TCP_IN (CONFLICTS with --fix-csf; see README)
  --dry-run              Print actions without changing the system
  --non-interactive      Assume 'yes' for prompts (use in automation with care)

Environment:
  This script is intended for Linux servers (cPanel optional). Run as root.
EOF
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check-only) CHECK_ONLY=1 ;;
      --fix-cpanel) CHECK_ONLY=0; FIX_CPANEL=1 ;;
      --fix-kernel) CHECK_ONLY=0; FIX_KERNEL=1 ;;
      --fix-csf) CHECK_ONLY=0; FIX_CSF=1 ;;
      --csf-strip-panel-ports) CHECK_ONLY=0; FIX_CSF_STRIP=1 ;;
      --purge-cpanel-sessions) CHECK_ONLY=0; PURGE_CPANEL_SESSIONS=1 ;;
      --list-domains) CHECK_ONLY=0; LIST_DOMAINS=1 ;;
      --domain-list-output=*) CHECK_ONLY=0; LIST_DOMAINS=1; DOMAIN_LIST_FILE="${1#*=}" ;;
      --remove-service-subdomains) CHECK_ONLY=0; REMOVE_SERVICE_SUBDOMAINS=1 ;;
      --fix-all) CHECK_ONLY=0; FIX_CPANEL=1; FIX_KERNEL=1; FIX_CSF=1 ;;
      --extra-hardening) CHECK_ONLY=0; EXTRA_HARDENING=1 ;;
      --extra-hardening-csf) CHECK_ONLY=0; EXTRA_HARDEN_CSF=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --non-interactive|-y) NON_INTERACTIVE=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (try --help)" ;;
    esac
    shift
  done

  require_root

  if [[ "$FIX_CSF" -eq 1 && "$FIX_CSF_STRIP" -eq 1 ]]; then
    die "Choose either --fix-csf (add ports) or --csf-strip-panel-ports (remove ports), not both."
  fi
  if [[ "$EXTRA_HARDEN_CSF" -eq 1 && "$FIX_CSF" -eq 1 ]]; then
    die "Choose either --extra-hardening-csf (fixed TCP_IN rewrite) or --fix-csf (merge panel ports), not both."
  fi

  local rest=$((FIX_CPANEL + FIX_KERNEL + FIX_CSF + FIX_CSF_STRIP + PURGE_CPANEL_SESSIONS + EXTRA_HARDENING + EXTRA_HARDEN_CSF))
  local only_list=0
  [[ "$LIST_DOMAINS" -eq 1 && "$REMOVE_SERVICE_SUBDOMAINS" -eq 0 && "$rest" -eq 0 ]] && only_list=1

  local remove_only=0
  [[ "$REMOVE_SERVICE_SUBDOMAINS" -eq 1 && "$LIST_DOMAINS" -eq 0 && "$rest" -eq 0 ]] && remove_only=1

  if [[ "$only_list" -eq 1 ]]; then
    log "=== Domain list (/etc/userdomains) ==="
    cpanel_emit_domain_list || exit 1
    exit 0
  fi

  if [[ "$remove_only" -eq 1 ]]; then
    log "=== Remove proxy/service subdomains (single-task mode) ==="
    cpanel_remove_proxy_and_service_subdomains || true
    exit 0
  fi

  if [[ "$LIST_DOMAINS" -eq 1 ]]; then
    log "=== Domain list (/etc/userdomains) ==="
    cpanel_emit_domain_list || true
  fi

  log "=== Assessment: cPanel CVE-2026-41940 ==="
  assess_cpanel_cve_2026_41940 || true

  log "=== Assessment: CSF / cPanel ports ==="
  FIX_CSF=0 csf_ensure_cpanel_ports || true

  log "=== Assessment: Kernel CVE-2026-31431 (Copy Fail) ==="
  assess_kernel_cve_2026_31431 || true

  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    log "Check-only mode. Use --fix-cpanel, --fix-kernel, --fix-csf, --csf-strip-panel-ports, --purge-cpanel-sessions, --list-domains, --remove-service-subdomains, --extra-hardening, --extra-hardening-csf, or --fix-all."
    exit 0
  fi

  if [[ "$FIX_CPANEL" -eq 1 ]]; then
    log "=== Remediation: cPanel ==="
    fix_cpanel_update
  fi
  if [[ "$FIX_KERNEL" -eq 1 ]]; then
    log "=== Remediation: kernel (algif_aead) ==="
    fix_kernel_alg_mitigation
  fi
  if [[ "$FIX_CSF" -eq 1 ]]; then
    log "=== Remediation: CSF ports (merge) ==="
    csf_ensure_cpanel_ports || true
  fi
  if [[ "$FIX_CSF_STRIP" -eq 1 ]]; then
    log "=== Remediation: CSF strip (lockdown ports) ==="
    csf_strip_panel_ports || true
  fi
  if [[ "$PURGE_CPANEL_SESSIONS" -eq 1 ]]; then
    log "=== Remediation: cPanel session flush ==="
    cpanel_flush_hot_sessions
  fi
  if [[ "$REMOVE_SERVICE_SUBDOMAINS" -eq 1 ]]; then
    log "=== Remediation: proxy & service subdomains ==="
    cpanel_remove_proxy_and_service_subdomains || true
  fi
  if [[ "$EXTRA_HARDENING" -eq 1 ]]; then
    apply_extra_hardening_bundle
  fi
  if [[ "$EXTRA_HARDEN_CSF" -eq 1 ]]; then
    log "=== Remediation: aggressive CSF (checklist) ==="
    apply_extra_hardening_csf_saeed
  fi

  log "Done."
}

main "$@"
