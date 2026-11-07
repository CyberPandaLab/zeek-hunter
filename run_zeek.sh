#!/bin/bash
# ======================================================================
# run_zeek.sh: generates Zeek logs for a whole tree of PCAP files
#   - one output folder per PCAP (same tree as the PCAPs)
#   - SMTP email body extraction (extract_files/smtp-<fuid>)
#   - smtp_received.log: Received headers (real origin of emails)
#   - parallel processing
#
# Usage: ./run_zeek.sh [PCAP_ROOT] [OUTPUT_ROOT]
#        Optional environment variables: MAX_JOBS, EXTRA_SCRIPTS
#   e.g.: ./run_zeek.sh /data/pcaps ./zeek_output
#        MAX_JOBS=8 EXTRA_SCRIPTS="" ./run_zeek.sh /data/pcaps ./zeek_output
#
# Zeek Forensics Hunter - Copyright (c) 2026 Frédéric Hauss - MIT License
# ======================================================================

export PATH=$PATH:/usr/local/zeek/bin:/opt/zeek/bin

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

# PCAP root folder (walked recursively: *.pcap and *.pcapng)
PCAP_ROOT="${1:-${PCAP_ROOT:-./pcaps}}"
# Output folder for Zeek logs
OUTPUT_ROOT="${2:-${OUTPUT_ROOT:-./zeek_output}}"
PCAP_ROOT="${PCAP_ROOT%/}"
OUTPUT_ROOT="$(mkdir -p "$OUTPUT_ROOT" && cd "$OUTPUT_ROOT" && pwd)"

BAD_LIST="$OUTPUT_ROOT/bad_pcaps.txt"
LOG_FILE="$OUTPUT_ROOT/zeek_run.log"

# Zeek script loaded on every run: extracts SMTP email bodies (HTML/text)
# and logs Received headers (smtp_received.log -> real origin of emails, phase 2)
ZEEK_SCRIPT="$OUTPUT_ROOT/extract_smtp.zeek"

# Extra Zeek scripts/packages, e.g. "ja3" if the package is installed (zkg install ja3)
# (needed for the ja3 field in ssl.log -> phase 8). EXTRA_SCRIPTS="" to run without it.
EXTRA_SCRIPTS="${EXTRA_SCRIPTS-ja3}"

# Maximum number of parallel Zeek processes (default: number of cores)
MAX_JOBS="${MAX_JOBS:-$(nproc 2>/dev/null || echo 4)}"

HUNTER="$(cd "$(dirname "$0")" && pwd)/zeek_hunter.py"

if ! command -v zeek >/dev/null 2>&1; then
    echo "[!] zeek not found in PATH"
    exit 1
fi
if [ ! -d "$PCAP_ROOT" ]; then
    echo "[!] PCAP folder not found: $PCAP_ROOT  (usage: $0 [PCAP_ROOT] [OUTPUT_ROOT])"
    exit 1
fi
# Absolute path required: Zeek runs from each PCAP's output folder (cd), where a relative
# path such as ./pcaps would no longer be valid.
PCAP_ROOT="$(cd "$PCAP_ROOT" && pwd)"

FAILED_LIST="$OUTPUT_ROOT/failed_pcaps.txt"
> "$BAD_LIST"
> "$LOG_FILE"
> "$FAILED_LIST"

# Zeek script generation (overwritten on every run)
cat > "$ZEEK_SCRIPT" <<'EOF'
# 1) Extracts SMTP email bodies (text/html, text/plain) to extract_files/smtp-<fuid>
#    The <fuid> matches the "fuids" field of smtp.log and the "fuid" field of files.log
# 2) Logs every Received header to smtp_received.log (uid + trans_depth = smtp.log key)
# 3) Hashes every file (MD5/SHA1/SHA256 in files.log: attachments, downloads) for IOC lookups
@load base/files/extract
@load frameworks/files/hash-all-files

module SMTPRecv;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time    &log;
        uid:         string  &log;
        id:          conn_id &log;
        trans_depth: count   &log;
        idx:         count   &log;   # header order: 0 = topmost (added by the last relay)
        received:    string  &log;
    };
}

redef record SMTP::Info += {
    recv_idx: count &default=0;
};

event zeek_init()
    {
    Log::create_stream(SMTPRecv::LOG, [$columns=Info, $path="smtp_received"]);
    }

event mime_one_header(c: connection, h: mime_header_rec)
    {
    if ( ! c?$smtp || h$name != "RECEIVED" )
        return;

    Log::write(SMTPRecv::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
                               $trans_depth=c$smtp$trans_depth, $idx=c$smtp$recv_idx,
                               $received=h$value]);
    ++c$smtp$recv_idx;
    }

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( f$source != "SMTP" || ! meta?$mime_type )
        return;

    if ( /^text\/(html|plain)/ in meta$mime_type )
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
                            [$extract_filename=fmt("smtp-%s", f$id)]);
    }
EOF

# Check the Zeek script before starting the jobs (syntax error / missing package = stop right away)
if ! zeek -a "$ZEEK_SCRIPT" $EXTRA_SCRIPTS >> "$LOG_FILE" 2>&1; then
    echo "[!] The Zeek script does not load (syntax error or missing package '$EXTRA_SCRIPTS'):"
    tail -n 20 "$LOG_FILE"
    echo "    Tip: EXTRA_SCRIPTS=\"\" $0 ...  to run without the ja3 package."
    exit 1
fi

echo "[*] PCAP  : $PCAP_ROOT"
echo "[*] Output: $OUTPUT_ROOT"
echo "[*] Looking for PCAP and PCAPNG files..."

mapfile -t pcap_files < <(find "$PCAP_ROOT" -type f \( -name "*.pcap" -o -name "*.pcapng" \))
total_files=${#pcap_files[@]}

if [ "$total_files" -eq 0 ]; then
    echo "[!] No pcap or pcapng file found in $PCAP_ROOT"
    exit 0
fi

echo "[*] Found $total_files files to process. Running in parallel (max $MAX_JOBS concurrent jobs)..."
echo ""

current=0

# Process one PCAP file
process_pcap() {
    local pcap="$1"

    # Quick check with tcpdump (unreadable PCAP -> bad_pcaps.txt)
    if tcpdump -r "$pcap" -c 1 >/dev/null 2>&1; then
        rel_path="${pcap#"$PCAP_ROOT"/}"
        base_path="${rel_path%.pcap}"
        base_path="${base_path%.pcapng}"
        out_dir="$OUTPUT_ROOT/$base_path"

        mkdir -p "$out_dir/extract_files"

        # Run from the output folder: the default ./extract_files/ prefix points there,
        # which avoids collisions between parallel runs (Zeek temporary files included).
        if ! (
            cd "$out_dir" && \
            zeek -C -r "$pcap" -e "redef Log::default_logdir=\"$out_dir\";" \
                 "$ZEEK_SCRIPT" $EXTRA_SCRIPTS >> "$LOG_FILE" 2>&1
        ); then
            echo "$pcap" >> "$FAILED_LIST"   # Zeek failed: details in zeek_run.log
        fi

        # Remove extract_files if it stayed empty (pcap without email)
        rmdir "$out_dir/extract_files" 2>/dev/null
    else
        echo "$pcap" >> "$BAD_LIST"
    fi
}

for pcap in "${pcap_files[@]}"; do
    ((current++))
    printf "[%d/%d] Processing: %s\r" "$current" "$total_files" "$pcap"

    process_pcap "$pcap" &

    # Limit the number of concurrent jobs
    while [ $(jobs -r | wc -l) -ge $MAX_JOBS ]; do
        sleep 0.1
    done
done

wait

nb_bad=$(wc -l < "$BAD_LIST")
nb_failed=$(wc -l < "$FAILED_LIST")
nb_bodies=$(find "$OUTPUT_ROOT" -type f -path "*/extract_files/smtp-*" 2>/dev/null | wc -l)
nb_recv=$(find "$OUTPUT_ROOT" -type f -name "smtp_received.log" 2>/dev/null | wc -l)

echo -e "\n\n[*] Done!"
echo "[*] Corrupted PCAPs: $nb_bad (list: $BAD_LIST)"
if [ "$nb_failed" -gt 0 ]; then
    echo "[!] Zeek failures: $nb_failed PCAP(s) (list: $FAILED_LIST; details: $LOG_FILE)"
else
    rm -f "$FAILED_LIST"
fi
echo "[*] Extracted email bodies: $nb_bodies"
echo "[*] smtp_received.log files (Received headers): $nb_recv"
echo "[*] Zeek log: $LOG_FILE"
echo "[*] Full analysis:"
echo "    python3 \"$HUNTER\" --root \"$OUTPUT_ROOT\" --mail-dir \"$OUTPUT_ROOT\" --phase all --out ./report"
