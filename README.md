# Zeek Forensics Hunter

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue) ![Zeek 5+](https://img.shields.io/badge/zeek-5%2B-informational) ![License MIT](https://img.shields.io/badge/license-MIT-green)

A network investigation toolkit built on PCAP captures, designed for threat hunting and incident response
(network forensics exercises, real incidents, CTFs…). It consists of two tools:

| Tool | Role |
|---|---|
| `run_zeek.sh` | Runs **Zeek** over a whole tree of PCAP files, in parallel. One log folder per PCAP, with extraction of email bodies and `Received` headers. |
| `zeek_hunter.py` | Analyzes **all those logs at once** in 10 hunting phases (mapping, IOCs, phishing, C2, lateral movement, leaks, DNS, exfiltration, TLS, proxy), plus per-session correlation. Prints a prioritized top list and exports to CSV/JSON. |

The Python script only uses the standard library: no `pip install` needed.

---

## Contents
1. [Repository layout](#1-repository-layout)
2. [Requirements and installation](#2-requirements-and-installation)
3. [Step 1: generate the Zeek logs](#3-step-1-generate-the-zeek-logs-run_zeeksh)
4. [Step 2: analyze with zeek_hunter](#4-step-2-analyze-with-zeek_hunter)
5. [Phases in detail](#5-phases-in-detail)
6. [Severities, scores and findings](#6-severities-scores-and-findings)
7. [Configuration files](#7-configuration-files)
8. [Exports](#8-exports)
9. [Suggested investigation workflow](#9-suggested-investigation-workflow)
10. [Times and time zones](#10-times-and-time-zones)
11. [Known limitations](#11-known-limitations)
12. [Troubleshooting](#12-troubleshooting)
13. [License](#13-license)

Ready-to-use commands are in **[EXAMPLES.md](EXAMPLES.md)**, the version history in **[CHANGELOG.md](CHANGELOG.md)**.

---

## 1. Repository layout

```
zeek-hunter/
├── README.md            this document
├── EXAMPLES.md          command cookbook by use case
├── CHANGELOG.md         version history
├── LICENSE              MIT license
├── check_env.sh         checks the requirements (Python, Zeek, ja3, syntax, line endings)
├── run_zeek.sh          step 1: PCAP -> Zeek logs
└── zeek_hunter.py       step 2: log analysis
```

## 2. Requirements and installation

| Component | Version / note |
|---|---|
| Linux | any distribution with bash (forensics-oriented distributions work well) |
| Zeek | 5.x or later (tested with 9.0.1), in `PATH` (or `/usr/local/zeek/bin`, `/opt/zeek/bin`) |
| Zeek `ja3` package | optional: used by phase 8 (JA3/JA3S). `zkg install ja3` |
| Python | 3.8 or later, no external dependency |
| tcpdump | used to skip corrupted PCAPs |

Installation:

```bash
# 1. Get the repository on the analysis machine
git clone https://github.com/CyberPandaLab/zeek-hunter.git
cd zeek-hunter
chmod +x run_zeek.sh check_env.sh

# 2. If the files went through Windows (error "$'\r': command not found"):
dos2unix *.sh *.py

# 3. Check the environment
./check_env.sh
```

`check_env.sh` checks the Python version, the script syntax, whether Zeek, the ja3 package and tcpdump are
present, Windows line endings and execute permissions.

## 3. Step 1: generate the Zeek logs (`run_zeek.sh`)

```bash
./run_zeek.sh <PCAP_FOLDER> <OUTPUT_FOLDER>
./run_zeek.sh --help
```

| Parameter | Default | Role |
|---|---|---|
| 1st argument / `PCAP_ROOT` | `./pcaps` | folder walked recursively (`*.pcap`, `*.pcapng`) |
| 2nd argument / `OUTPUT_ROOT` | `./zeek_output` | output folder (created if needed) |
| `MAX_JOBS` | number of cores | concurrent Zeek processes |
| `EXTRA_SCRIPTS` | `ja3` | extra Zeek scripts or packages to load (`""` = none) |

What the script produces:

```
<OUTPUT_FOLDER>/
├── bad_pcaps.txt            unreadable PCAPs (skipped)
├── failed_pcaps.txt         PCAPs on which Zeek failed (only created when there are failures)
├── zeek_run.log             Zeek output (errors, warnings)
├── extract_smtp.zeek        generated Zeek script (extraction + Received)
└── <same tree as the PCAPs>/<pcap_name>/
    ├── conn.log, dns.log, http.log, ssl.log, smtp.log, files.log, x509.log, smb_files.log, ...
    ├── smtp_received.log    Received headers of each email (real origin)
    └── extract_files/
        └── smtp-<fuid>      email bodies (HTML or text), already decoded, WITHOUT extension
```

Key points:
- **Email bodies have no extension. This is expected.** The `<fuid>` in the name links them to `files.log`
  (`fuid` field) and `smtp.log` (`fuids` field). `zeek_hunter` reads them as they are.
- **Startup check:** the Zeek script is tested before the jobs start. A syntax error or a missing ja3
  package stops everything right away, with the error message.
- **Re-runs:** running the script again rewrites the logs in place. Empty the output folder to start from
  scratch.

## 4. Step 2: analyze with `zeek_hunter`

> Always run the script **from the same working folder**. It creates and reads its configuration files there:
> `whitelist.txt`, `ioc_*.txt`, `keywords.txt`, etc.

### Interactive mode (menu)

```bash
python3 zeek_hunter.py --root <OUTPUT_FOLDER> --out ./report
```

```
0-9  hunting phases (see § 5)
c    correlation by uid / IP / keyword (session timeline)
s    web summary (src/dst IPs, host/URI, first/last seen) + keyword
t    triage of the remaining public IPs (with/without a DNS name)
w    whitelist management and IOC ingestion (URLhaus, SSLBL, cloud ranges)
e    full run: phases 0-9 + s + per-host score + export
r    re-index the tree / clear caches
q    quit
```

### Command-line mode

```bash
python3 zeek_hunter.py --root <OUTPUT_FOLDER> --phase all --out ./report      # everything, non-interactive
python3 zeek_hunter.py --root <OUTPUT_FOLDER> --phase 2 9 --out ./report      # selected phases
```

| Option | Role |
|---|---|
| `--root FOLDER` | Zeek log root (else the `ZEEK_LOG_ROOT` variable, else `./zeek_output`) |
| `--phase …` | `0`…`9`, `s`, `t`, or `all` (= menu `e`); several values allowed |
| `--out FOLDER` | enables CSV/JSON exports |
| `-j N` / `--jobs N` | number of analysis processes (default: CPU count) |
| `--mail-dir FOLDER` | email bodies / `.eml` for phase 2 (default: `./zeek_output`, else `--root`) |
| `--ext ".exe\|.zip\|.dll"` | attachment and download extensions targeted by phase 2 |
| `--detail` | phase 2: per-email details |
| `--keyword "a\|b"` | keyword for the web summary `s`, or correlation when used without `--phase` |
| `--correlate IP\|UID` | correlated timeline of a host or a session |
| `--since` / `--until` | UTC time window (`2024-05-01 15:00`) for correlation |
| `--limit N` | number of sessions shown in correlation (default 60) |
| `--with-events` | correlation: only sessions with application events |
| `--ingest FILE` | ingests a URLhaus (abuse.ch) CSV/ZIP into `ioc_ips.txt` / `ioc_domains.txt` |
| `--ingest-tls FILE` | ingests an SSLBL CSV (JA3 / certificate fingerprints) |
| `--learn-whitelist` | learns the IP whitelist from `whitelist.txt` + DNS/SNI/Host |
| `--import-ranges FILE [--tags …]` | imports official ranges (AWS, Google, Microsoft, Cloudflare) |
| `--version` | prints the version |

## 5. Phases in detail

| Phase | Name | Logs | What it looks for |
|---|---|---|---|
| **0** | Mapping | conn | private IPs; top 20 non-whitelisted public IPs (connections, volume, peers); flows grouped by source |
| **1** | Discovery & threat intel | conn, http, dns, ssl | flows to **IOC IPs**; **IOC domains** in a summary view (one line per domain, DNS/HTTP/TLS counters, first → last seen, one line per source); suspicious User-Agents (curl, python, powershell…) |
| **2** | Spearphishing | smtp, files, smtp_received, extracted bodies, http, ssl, dns | **email triage** (per-email score, top suspicious emails, link domains, senders) + suspicious **downloads** (targeted extensions, executable MIME) |
| **3** | C2 | conn | non-standard ports to the outside; **beaconing** (periodic connections) |
| **4** | Lateral movement | conn | internal SMB/RDP/WinRM/RPC flows; **fan-out** (one source to ≥ 3 targets); admin ports exposed to the Internet; **top 5 pivots** (A → B → C) |
| **5** | Leaks / sensitive files | smb_files | SMB file names containing a `keywords.txt` keyword (ntds.dit, id_rsa, backup…) |
| **6** | DNS anomalies | dns | tunneling (many subdomains), DGA (entropy), NXDOMAIN, repeated TXT/NULL |
| **7** | Exfiltration & scans | conn | top outbound volumes; horizontal and vertical scans (failed connections) |
| **8** | TLS | ssl, x509 | IOC JA3/JA3S, IOC certificates, rare JA3, certificate anomalies (self-signed, expired, SNI ≠ CN…) |
| **9** | Proxy / HTTP | http | **CONNECT** destinations with `[IOC]` `[BCN]` `[VOL]` `[rare]` tags and clients by volume; HTTP beaconing per (client, host) |

### Phase 2: email signals

| Signal | Score | Min. severity |
|---|---|---|
| link whose URL or text contains a `LINK_KEYWORDS` keyword (default: `download`), outside `whitelist.txt` domains | +10 | **critical** |
| link to an IOC domain | +6 | high |
| email RECEIVED from the Internet whose sender has the **same domain as the recipient** (spoofing) | +6 | high |
| attachment with a targeted extension (`--ext`) | +4 | |
| **suspicious mailing tool** (PHPMailer, GoPhish, swaks, python…) | +3 | medium |
| **unusual sending client** for the domain (e.g. Thunderbird while the domain uses Outlook) | +3 | medium |
| link: literal IP, punycode, displayed text ≠ destination | +3 per link (max 10) | |
| link visited after receipt (http/ssl/dns, within 7 days) | +2, or +4 if the link is flagged | |
| MAIL FROM ≠ From, Reply-To ≠ From | +2 each | |
| URL shortener | +1 | |
| lure subject (invoice, password, urgent…) | +1 | |

For each email, the phase also shows:
- the **relay seen in the PCAP**, with its HELO;
- the **real origin**, read from the `Received` headers: `203.0.113.25 (mail.example.net)`;
- the **`Date:`** header in the sender's time zone.

### Phase 9: CONNECT destination tags

| Tag | Meaning |
|---|---|
| `[IOC]` | domain listed in the IOCs (see the limitation on shared platforms, § 11) |
| `[BCN]` | at least one client has a regular rhythm towards this host (beaconing) |
| `[VOL]` | at least one client sent ≥ `PROXY_VOLUME_MIN` (10,000) requests to this host: typical of a C2 behind a CDN, or of an ad page left open |
| `[rare]` | a single client |

## 6. Severities, scores and findings

Every detection produces a **finding** (phase, severity, source, destination, type, detail, first seen, log, uid).

| Severity | Weight in the per-host score |
|---|---|
| critical | 100 |
| high | 25 |
| medium | 5 |
| low | 1 |
| info | 0 |

At the end of a run (`--phase …` or menu `e`), the **internal host score** ranks each private IP by its findings.
For each severity, the host gets `weight x (1 + log2(number of findings))`, and these are added up. The volume
counts with diminishing returns (100 findings weigh about 7.6 times one finding, not 100 times), so a single
CRITICAL always outweighs any number of LOW findings. This is the list of machines to investigate first.

## 7. Configuration files

They are created automatically on the first run, in the current folder. Lines starting with `#` are comments.

| File | Format | Role |
|---|---|---|
| `whitelist.txt` | one domain per line | legitimate domains, subdomains included (`microsoft.com` covers `x.microsoft.com`) |
| `ip_whitelist*.txt` | IP or CIDR per line | legitimate IPs; **all** `ip_whitelist*.txt` files are read |
| `ioc_domains.txt` | `domain\|threat` | malicious domains |
| `ioc_ips.txt` | `ip\|threat` | malicious IPs |
| `ioc_ja3.txt` | `ja3_md5\|threat` | malicious JA3/JA3S fingerprints |
| `ioc_certs.txt` | `fingerprint\|threat` | malicious certificate fingerprints (SHA1/SHA256) |
| `keywords.txt` | word or `re:regex` (text after two spaces and `#` is a comment) | phase 5 keywords (SMB): sensitive names (ntds.dit, id_rsa, backup…) and file extensions grouped by family (executables, code, archives, documents, images) |

An IOC always overrides the whitelist.

Config files are never overwritten: to get new defaults (e.g. the `keywords.txt` extension list), delete or
rename the old file and run the script again.

Thresholds are set in the `CONFIGURATION` section at the top of `zeek_hunter.py`:

| Constant | Default | Effect |
|---|---|---|
| `BEACON_MIN_CONN`, `BEACON_JITTER`, `BEACON_RATIO` | 10, 0.20, 0.80 | beaconing sensitivity |
| `MAX_BEACON_TS` | 3,000 | timestamp sample size per pair (covers the whole period) |
| `FANOUT_MIN` | 3 | minimum number of targets for a fan-out |
| `EXFIL_MIN_BYTES` | 50 MB | exfiltration threshold |
| `TOP_PUBLIC_IPS` | 20 | phase 0: public IPs shown |
| `IOC_SRC_LIMIT` | 10 | phase 1: sources per IOC domain |
| `TOP_PIVOTS` | 5 | phase 4: pivots shown |
| `LINK_KEYWORDS` | `["download"]` | phase 2: keywords that make a link critical |
| `UA_BASELINE_MIN`, `UA_RARE_RATIO` | 5, 0.10 | phase 2: unusual sending client |
| `CLICK_WINDOW` | 7 days | phase 2: max delay between receipt and a link visit |
| `PROXY_CLIENTS_SHOWN`, `PROXY_VOLUME_MIN` | 6, 10,000 | phase 9 |
| `DISPLAY_LIMIT` | 200 | max lines on screen per section (the rest goes to the export) |

## 8. Exports

With `--out FOLDER` (or menu `e`, default `./report`), each file is timestamped (`_YYYYMMDD_HHMMSS`):

| File | Content |
|---|---|
| `summary_*.txt` | **read this first**: counts by severity/phase/type, top 15 hosts, all CRITICAL/HIGH findings |
| `host_scores_*.csv` | score per internal host, with the count of findings per severity |
| `findings_*.csv` / `.json` | all findings |
| `emails_*.csv` | all emails: score, severity, relay, origin, sending client, header date, attachments (with SHA256), reasons… |
| `email_links_*.csv` | all extracted links, with alerts and visits |
| `ioc_domains_*.csv` | phase 1: details of accesses to IOC domains |
| `public_ips_*.csv` | phase 0: all non-whitelisted public IPs |
| `pivots_*.csv` | phase 4: all pivots |
| `proxy_connect_*.csv` | phase 9: all CONNECT destinations, with tags and clients |
| `suspicious_downloads_*.csv`, `user_agents_*.csv`, `web_summary_*.csv` | details of phases 1, 2 and s |
| `timeline_*.csv` | correlation (`c` / `--correlate` / `--keyword`) |

CSV times are written as `2024-05-01 23:15:00 UTC`. Spreadsheets keep them as is (see § 10).

## 9. Suggested investigation workflow

1. **Overview:** `--phase all --out ./report`, then read `summary_*.txt` and `host_scores_*.csv`.
2. **Reduce the noise:** add recurring legitimate domains to `whitelist.txt` (ad networks, well-known CDNs),
   then `--learn-whitelist`. Run again.
3. **Entry point:** phase 2. Critical/high emails, origin, sending client, was a link visited? Then downloads.
4. **Remote control:** phases 3 and 9 (beaconing, `[VOL]`/`[BCN]` behind the proxy), phase 8 (JA3, certificates).
5. **Spread:** phase 4 (fan-out, pivots), phase 5 (sensitive files).
6. **Impact:** phase 7 (exfiltration), phase 6 (DNS tunneling).
7. **Rebuild the timeline:** `--correlate <IP|uid>` or `--keyword <domain>` on each suspicious item,
   with `--out` to keep the timeline.

## 10. Times and time zones

- **All times shown are UTC** (`Z` suffix). They are the packet timestamps of the PCAP, which Zeek writes in the
  `ts` field of every log. **A PCAP holds no time zone.**
- **Wireshark** shows the machine's local time by default. To compare:
  *View → Time Display Format → UTC Date and Time of Day*.
- **Spreadsheets:** a `…Z` value in a CSV may be converted to local time (`23:15:00Z` shown as `00:15:00` the
  next day in Paris in winter). Exports therefore write `… UTC` to prevent that conversion.
- **Email headers:** `Date:` and `Received` use each server's or client's time zone (`-0500`, `-0800`…).
  They describe the same instant, written differently.

## 11. Known limitations

- **IOCs on shared platforms:** URLhaus ingestion only keeps the host name of each URL. A malicious URL hosted
  on Dropbox, GitHub, jsDelivr, Firebase, Cloudinary… therefore turns the whole domain into an IOC. Such `[IOC]`
  hits must be confirmed by hand (exact URL over plain HTTP, correlation).
- **HTTPS:** behind a proxy, only the host of the `CONNECT` request is visible, with no URL or file.
  Without a proxy, only the SNI is (phase 8).
- **Email origin:** only the IP recorded by **your** gateway (first `Received` header with a public IP) is
  reliable. Older headers are written by the sender and can be forged. Without `smtp_received.log` (older
  logs), the origin comes from the `path` field of `smtp.log`, without a name.
- **Unusual sending client:** a domain's baseline needs at least 5 emails from that domain in the capture. An
  employee writing from a phone can trigger the signal, hence the medium level only.
- **Pivots:** domain controllers and file servers naturally have inbound and outbound admin flows. Check the
  delay between entry and hop, and the nature of the targets.
- **Beaconing:** to limit memory, the timestamps of each (client, destination) pair are sampled at regular
  intervals (at most `MAX_BEACON_TS` = 3,000 per file) over the **whole** period. An irregular rhythm
  (jitter > 20 %) is not detected.
- **Volume:** the analysis runs in parallel (`-j`), but `conn.log` is kept in memory (cache). Plan for several
  GB of RAM for captures spanning several weeks.

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `$'\r': command not found` | Windows line endings: `dos2unix *.sh *.py` |
| `zeek not found` | add Zeek to `PATH`, or install it in `/opt/zeek` |
| `The Zeek script does not load` | see `zeek_run.log`; without ja3: `EXTRA_SCRIPTS="" ./run_zeek.sh …` |
| `Zeek failures: N PCAP(s)` | see `failed_pcaps.txt` and `zeek_run.log` |
| Phase 2: `0 link(s) in 0 bodies` | wrong bodies folder: `--mail-dir <OUTPUT_FOLDER>` |
| Phase 2: `smtp_received.log missing` | logs generated by an older version: run `run_zeek.sh` again |
| Phase 8: `JA3 in logs: no` | ja3 package missing when `run_zeek.sh` ran |
| `Zeek log root not found` / no logs | `--root` must point to the **output folder** of `run_zeek.sh`, not to the PCAPs |
| Times off by one or more hours | see § 10 (UTC everywhere in the tool) |
| Too much noise | extend `whitelist.txt`, then `--learn-whitelist`, and/or import official ranges (`w` → 6) |

## 13. License

Released under the **MIT** license: see [LICENSE](LICENSE). Copyright (c) 2026 Frédéric Hauss.

This tool is meant for analyzing captures you are authorized to examine (your own networks, exercises,
authorized engagements). Its results are investigation leads, not proof: every finding must be verified.
