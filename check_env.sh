#!/bin/bash
# ======================================================================
# check_env.sh: checks that this machine can run run_zeek.sh and zeek_hunter.py
# Usage: ./check_env.sh
#
# Zeek Forensics Hunter - Copyright (c) 2026 Frédéric Hauss - MIT License
# ======================================================================

export PATH=$PATH:/usr/local/zeek/bin:/opt/zeek/bin
DIR="$(cd "$(dirname "$0")" && pwd)"
ok=0; ko=0
err="$(mktemp)"; trap 'rm -f "$err"' EXIT

pass() { echo "  [OK]   $1"; ok=$((ok + 1)); }
fail() { echo "  [FAIL] $1"; ko=$((ko + 1)); }
warn() { echo "  [WARN] $1"; }

echo "[*] Checking the environment"

# --- Python ---
if command -v python3 >/dev/null 2>&1; then
    v=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
        pass "python3 $v (>= 3.8 required, standard library only)"
    else
        fail "python3 $v is too old (>= 3.8 required)"
    fi
    # Syntax check without writing a __pycache__ folder next to the script
    if python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' \
            "$DIR/zeek_hunter.py" 2>"$err"; then
        pass "zeek_hunter.py: valid syntax"
    else
        fail "zeek_hunter.py: syntax error"
        cat "$err"
    fi
else
    fail "python3 not found"
fi

# --- Zeek ---
if command -v zeek >/dev/null 2>&1; then
    pass "$(zeek --version 2>/dev/null | head -n1)"
    if zeek -a ja3 >/dev/null 2>&1; then
        pass "Zeek ja3 package available (ja3 field in ssl.log, phase 8)"
    else
        warn "Zeek ja3 package missing: install it (zkg install ja3) or run run_zeek.sh with EXTRA_SCRIPTS=\"\""
    fi
else
    fail "zeek not found (PATH, /usr/local/zeek/bin, /opt/zeek/bin)"
fi

# --- System tools ---
for t in tcpdump find nproc; do
    if command -v "$t" >/dev/null 2>&1; then pass "$t"; else fail "$t not found"; fi
done

# --- Windows line endings (files copied from Windows) ---
for f in "$DIR"/*.sh "$DIR"/*.py; do
    if grep -q $'\r' "$f" 2>/dev/null; then
        fail "$(basename "$f") has Windows line endings: dos2unix \"$f\""
    fi
done

# --- Execute permissions ---
for f in "$DIR"/run_zeek.sh "$DIR"/check_env.sh; do
    [ -x "$f" ] || warn "$(basename "$f") is not executable: chmod +x \"$f\" (or run it with bash)"
done

echo ""
echo "[*] Result: $ok OK, $ko FAIL"
[ "$ko" -eq 0 ] && echo "[+] Ready." || echo "[!] Fix the FAIL items before running the tool."
exit "$ko"
