# Command examples

The paths, IP addresses, domains and identifiers below are **fictitious examples** (private addresses or
RFC 5737 documentation ranges, `example.*` domains). Adjust `PCAP` and `LOGS` to your case:

```bash
PCAP=/data/case01/pcaps
LOGS=/data/case01/zeek_output
cd ~/zeek-hunter                  # working folder: the config (whitelist, IOCs...) is created here
```

---

## 0. Check the installation

```bash
./check_env.sh
```

## 1. Generate the Zeek logs

```bash
# Standard case
./run_zeek.sh "$PCAP" "$LOGS"

# Smaller machine: at most 8 Zeek processes
MAX_JOBS=8 ./run_zeek.sh "$PCAP" "$LOGS"

# Without the ja3 package (not installed)
EXTRA_SCRIPTS="" ./run_zeek.sh "$PCAP" "$LOGS"

# Several PCAP disks into the same log folder (run one after the other)
./run_zeek.sh /mnt/disk1/pcaps "$LOGS/disk1"
./run_zeek.sh /mnt/disk2/pcaps "$LOGS/disk2"

# Checks after generation
cat "$LOGS/bad_pcaps.txt"                                    # unreadable PCAPs
cat "$LOGS/failed_pcaps.txt" 2>/dev/null                     # PCAPs on which Zeek failed
grep -i -m 20 error "$LOGS/zeek_run.log"                     # Zeek errors
find "$LOGS" -path '*/extract_files/smtp-*' | wc -l          # number of extracted email bodies
find "$LOGS" -name smtp_received.log | wc -l                 # number of smtp_received.log files
```

## 2. Full analysis (recommended first)

```bash
python3 zeek_hunter.py --root "$LOGS" --phase all --out ./report
less ./report/summary_*.txt
```

## 3. Interactive mode

```bash
python3 zeek_hunter.py --root "$LOGS" --out ./report
```

## 4. Targeted phases

```bash
# Mapping + threat intel
python3 zeek_hunter.py --root "$LOGS" --phase 0 1

# Phishing: email triage with the details of each flagged email
python3 zeek_hunter.py --root "$LOGS" --phase 2 --mail-dir "$LOGS" --detail --out ./report

# Phishing: custom attachment / download extensions
python3 zeek_hunter.py --root "$LOGS" --phase 2 --ext ".exe|.dll|.js|.hta|.iso|.zip" --out ./report

# C2: direct beaconing + behind the proxy + TLS
python3 zeek_hunter.py --root "$LOGS" --phase 3 9 8 --out ./report

# Spread: lateral movement, pivots, sensitive SMB files
python3 zeek_hunter.py --root "$LOGS" --phase 4 5 --out ./report

# Impact: exfiltration, scans, DNS
python3 zeek_hunter.py --root "$LOGS" --phase 7 6 --out ./report

# More power (16 processes)
python3 zeek_hunter.py --root "$LOGS" --phase all -j 16 --out ./report
```

## 5. Correlation / timeline

```bash
# Everything a host did (first 60 sessions)
python3 zeek_hunter.py --root "$LOGS" --correlate 10.0.10.25 --out ./report

# Only sessions with application events, within a time window (UTC)
python3 zeek_hunter.py --root "$LOGS" --correlate 10.0.10.25 --with-events \
    --since "2024-05-01 08:00" --until "2024-05-01 12:00" --limit 200 --out ./report

# One specific session (Zeek uid shown in the results)
python3 zeek_hunter.py --root "$LOGS" --correlate C1a2B3c4D5e6F7g8H9

# All sessions to a domain (HTTP Host, URI, SNI, DNS)
python3 zeek_hunter.py --root "$LOGS" --keyword c2.example.com --with-events --out ./report

# Several keywords
python3 zeek_hunter.py --root "$LOGS" --keyword "example.net|example.org" --out ./report
```

## 6. Web summary / triage

```bash
# All web traffic outside the whitelist (src -> dst, host/URI, first/last seen)
python3 zeek_hunter.py --root "$LOGS" --phase s --out ./report

# Web summary filtered on a keyword
python3 zeek_hunter.py --root "$LOGS" --phase s --keyword example.com --out ./report

# Remaining public IPs, with or without a DNS name (whitelist candidates / suspects)
python3 zeek_hunter.py --root "$LOGS" --phase t
```

## 7. Threat intel and whitelists

```bash
# URLhaus IOCs (abuse.ch): https://urlhaus.abuse.ch/downloads/csv/
python3 zeek_hunter.py --ingest ./urlhaus_csv.zip

# SSLBL IOCs (abuse.ch): JA3 and certificate fingerprints
python3 zeek_hunter.py --ingest-tls ./sslblacklist.csv
python3 zeek_hunter.py --ingest-tls ./ja3_fingerprints.csv

# Add legitimate domains, then learn the matching IPs
echo "office.com"    >> whitelist.txt
echo "gstatic.com"   >> whitelist.txt
python3 zeek_hunter.py --root "$LOGS" --learn-whitelist

# Import official ranges (e.g. specific AWS services, not the whole CLOUDFRONT/AMAZON sets)
python3 zeek_hunter.py --import-ranges ./ip-ranges.json --tags S3 EC2
python3 zeek_hunter.py --import-ranges ./ServiceTags_Public.json --tags AzureCloud
python3 zeek_hunter.py --import-ranges ./cloudflare-ips-v4.txt

# Add an IOC by hand
echo "evil.example.com|phishing" >> ioc_domains.txt
echo "203.0.113.45|c2"           >> ioc_ips.txt
```

## 8. Working with the exports on the command line

```bash
# Most suspicious hosts
column -s, -t < ./report/host_scores_*.csv | head -20

# Critical/high findings, sorted by date
grep -E ',(critical|high),' ./report/findings_*.csv | sort -t, -k7

# Critical emails
grep ',critical,' ./report/emails_*.csv

# CONNECT destinations tagged volume / beaconing
grep -E '\[(VOL|BCN)\]' ./report/proxy_connect_*.csv
```

## 9. Direct Zeek queries (complement)

```bash
# Fields of one email in smtp.log (relay, HELO, path, client)
grep C1a2B3c4D5e6F7g8H9 $(find "$LOGS" -name smtp.log) | zeek-cut -d ts helo mailfrom rcptto subject path user_agent

# Received headers of one email
grep C1a2B3c4D5e6F7g8H9 $(find "$LOGS" -name smtp_received.log) | zeek-cut idx received

# Email body file from its fuid
find "$LOGS" -name 'smtp-F1a2B3c4D5e6F7g8H9'
```
