# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Default `keywords.txt` (phase 5, SMB): adds 42 file extensions grouped by family (system and executables,
  code and development, archives, documents, images). Each is matched as a whole extension (`re:\.ext\b`), so
  `.js` does not match `.json` and `.log` does not match `.login`. `.zip`, `.tar` and `.sql` move from the
  backups section to their families.
- `audit` is commented out by default (too noisy).
- `keywords.txt` accepts inline comments (two spaces, then `#`).

## [1.0.0] - 2026-11-07

First public release.

### Features

**Collection (`run_zeek.sh`)**
- Runs Zeek in parallel over a whole tree of PCAP files (`*.pcap`, `*.pcapng`), one log folder per PCAP.
- Skips unreadable PCAPs (`bad_pcaps.txt`), lists PCAPs on which Zeek fails (`failed_pcaps.txt`) and checks
  the Zeek script (`zeek -a`) before starting the jobs.
- Extracts email bodies (`extract_files/smtp-<fuid>`) and writes an `smtp_received.log` (`Received` headers).
- Hashes every file seen (MD5/SHA1/SHA256 in `files.log`), so attachments and downloads can be checked
  against IOCs.
- Paths as arguments (relative or absolute); `MAX_JOBS` and `EXTRA_SCRIPTS` (`ja3` package) as environment
  variables.

**Analysis (`zeek_hunter.py`)**
- Standard library only; TSV, JSON and `.gz` logs; parallel analysis (`-j`).
- 10 phases: mapping, threat intel (IOC IPs/domains, User-Agents), spearphishing (email triage and scoring,
  real origin, sending client, links visited after receipt, suspicious downloads), C2 (non-standard ports,
  beaconing), lateral movement (fan-out, pivots), SMB leaks, DNS anomalies, exfiltration and scans,
  TLS (JA3/JA3S, certificates), proxy (CONNECT destinations, HTTP beaconing).
- Correlation by uid / IP / keyword (session timeline), web summary, public IP triage.
- Domain and IP whitelists, IP whitelist learning, official range import (AWS, Google, Microsoft,
  Cloudflare), URLhaus and SSLBL IOC ingestion.
- Per-host score, text summary, CSV/JSON exports (times written as `… UTC`).
- All messages, menus, exports and documentation in English.
- Tested end to end with Zeek 9.0.1 and the `ja3` package (SMTP, HTTP, proxy CONNECT, DNS, TLS, RDP traffic).

### Fixes and improvements over the pre-release versions
- **Beaconing (phases 3 and 9):** timestamps are now sampled at regular intervals over the whole period,
  instead of keeping only the first 3,000 per file. Connection counts and first/last seen stay exact, and the
  median interval shown is the real one.
- **Phase 9, `[VOL]` tag:** based on the most active client (no longer on the per-client average). The
  `Req/cl.` column becomes `Max/cl.`, and only clients above the threshold produce a `connect_volume` finding.
- **Per-host score:** computed in a single pass over the findings (much faster on large datasets).
- **`run_zeek.sh`:** a PCAP folder given as a relative path (e.g. `./pcaps`) made Zeek fail on every file; it
  is now converted to an absolute path. Zeek failures are listed and counted. Paths containing `[` `]` work.
- **Phase 1:** one line per (source, IOC IP, port) instead of one per Zeek service.
- **Phase 4:** internal flow display limited to `DISPLAY_LIMIT` (everything stays in the findings).
- **Web summary:** a CONNECT request without a `Host` header is attached to the requested host (not to the
  proxy IP), so the whitelist applies to it.
- **Triage:** the `[IOC]` tag is also shown for IPs that have a DNS name.
- Clear message and exit code 1 when the log root (`--root`) does not exist; the `w` submenu no longer
  crashes at end of input; `--version` option.
- The correlation function is renamed `correlate` (it is unrelated to phase 9).
- Generic default paths (`./pcaps`, `./zeek_output`) and anonymized documentation examples.
