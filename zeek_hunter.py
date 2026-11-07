#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zeek Forensics Hunter: threat hunting and incident response on Zeek logs.

Analyzes a whole tree of Zeek logs at once (one folder per PCAP, as produced by run_zeek.sh):
10 hunting phases (mapping, threat intel, phishing, C2, lateral movement, SMB leaks, DNS, exfiltration,
TLS, proxy), per-session correlation (uid), per-host scoring and CSV/JSON exports.
Python standard library only (3.8+).

Copyright (c) 2026 Frédéric Hauss
MIT License: see the LICENSE file.
"""

import argparse
import bisect
import csv
import email
import email.policy
import email.utils
import glob
import html
import gzip
import io
import ipaddress
import json
import math
import os
import re
import sys
import textwrap
import threading
import urllib.parse
import zipfile
import builtins
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from email.header import decode_header, make_header
from functools import lru_cache
from statistics import median

VERSION = "1.0.0"

# ======================================================================
# CONFIGURATION
# ======================================================================
LOG_ROOT = os.environ.get("ZEEK_LOG_ROOT", "./zeek_output")
WHITELIST_FILE = "whitelist.txt"
IP_WHITELIST_FILE = "ip_whitelist.txt"
IOC_DOMAINS_FILE = "ioc_domains.txt"
IOC_IPS_FILE = "ioc_ips.txt"
KEYWORD_FILE = "keywords.txt"
IOC_JA3_FILE = "ioc_ja3.txt"
IOC_CERTS_FILE = "ioc_certs.txt"

JOBS = os.cpu_count() or 1
DEFAULT_EXTS = [".exe", ".zip", ".iso", ".lnk", ".scr"]
CLI_EXTS = None
STD_PORTS = {80, 443, 53}
LATERAL_PORTS = {445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-TLS", 135: "DCE-RPC"}
PE_MIMES = ("x-dosexec", "x-msdownload", "x-msdos-program", "portable-executable")
HIGH_VALUE_KEYWORDS = {"ntds.dit", "id_rsa", "id_dsa", "authorized_keys", "shadow"}
FAIL_STATES = {"S0", "REJ", "RSTOS0", "RSTRH"}

# Detection thresholds (tune them for each case)
MAX_BEACON_TS = 3000          # max timestamp sample size per triplet (covers the whole period)
BEACON_MIN_CONN = 10
BEACON_JITTER = 0.20          # tolerance around the median interval
BEACON_RATIO = 0.80           # required share of "regular" intervals
FANOUT_MIN = 3                # number of distinct internal targets on a lateral port
TOP_PIVOTS = 5                # phase 4: pivots shown
PROXY_CLIENTS_SHOWN = 6       # phase 9: clients shown per CONNECT destination (with their request count)
PROXY_VOLUME_MIN = 10000      # phase 9: [VOL] tag when at least one client sends >= N CONNECT requests to the host
EXFIL_MIN_BYTES = 50 * 1024 * 1024
SCAN_MIN_TARGETS = 50
DNS_LABEL_MIN = 12
DNS_ENTROPY = 3.4
DNS_DGA_MIN = 10
DNS_TUNNEL_MIN_SUB = 100
DNS_NX_MIN = 50
DNS_TXT_MIN = 50
DISPLAY_LIMIT = 200
TOP_PUBLIC_IPS = 20           # phase 0: public IPs shown, and max destinations per flow line
IOC_SRC_LIMIT = 10            # phase 1: sources shown per IOC domain
JA3_RARE_MAX_HOSTS = 1
CERT_SHORT_DAYS = 3
CERT_LONG_DAYS = 3650
SUSPECT_CERT_MARKERS = ("internet widgits", "default company", "snakeoil", "localhost", "acme co")

# Phase 2 (emails)
TOP_MAILS = 25                # suspicious emails shown
TOP_LINK_DOMAINS = 20         # link domains shown
TOP_SENDERS = 10              # sender domains shown
CLICK_WINDOW = 7 * 86400      # a link counts as "visited" only within 7 days of receipt
DETAIL_MAILS = None           # None = ask in interactive mode; True/False via --detail
DEFAULT_MAIL_DIR = "./zeek_output"   # default folder for email bodies (phase 2)
# Keywords that make a link "critical" (searched in the URL and the displayed text, case-insensitive).
# A link to a whitelist.txt domain is only flagged (low), not escalated.
LINK_KEYWORDS = ["download"]
# Sending client (User-Agent / X-Mailer): a rare client for a sender domain is suspicious when that domain
# has at least UA_BASELINE_MIN emails and the client accounts for at most UA_RARE_RATIO of them.
UA_BASELINE_MIN = 5
UA_RARE_RATIO = 0.10
SUBJECT_LURES = re.compile(
    r"(password|mot de passe|urgent|invoice|facture|payment|paiement|verif|vérif|account|compte|"
    r"suspend|expir|reset|login|connexion|docusign|wire|virement|delivery|livraison|security|sécurité)", re.I)

UNSET = frozenset(("-", "(empty)", ""))

# Log data (email subjects, URLs, User-Agents...) is untrusted: control characters (ESC, BEL, NUL...)
# and bidi marks are neutralized before anything is printed to the terminal.
_CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def print(*args, **kwargs):  # noqa: A001 (surcharge volontaire)
    builtins.print(*[_CTRL_RE.sub("·", a) if isinstance(a, str) else a for a in args], **kwargs)


_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_LOG_NAME_RE = re.compile(r"(?P<kind>[A-Za-z0-9_]+)(?:\.[^/]*?)?\.log(?:\.gz)?")

FINDINGS = []
_FILE_INDEX = None
_CONN_CACHE = None
_NAMES_CACHE = None
_IOC_LOCK = threading.Lock()
CTX = {}  # context read by the workers


# ======================================================================
# ENVIRONMENT / CONFIG FILES
# ======================================================================
def init_environment():
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write("au.download.windowsupdate.com\nwindowsupdate.com\nmicrosoft.com\n")
    if not os.path.exists(IP_WHITELIST_FILE):
        with open(IP_WHITELIST_FILE, "w") as f:
            f.write("20.0.0.0/8\n13.107.0.0/16\n40.74.0.0/15\n")
    if not os.path.exists(IOC_DOMAINS_FILE):
        with open(IOC_DOMAINS_FILE, "w") as f:
            f.write("# Format: domain|threat_type\n")
    if not os.path.exists(IOC_IPS_FILE):
        with open(IOC_IPS_FILE, "w") as f:
            f.write("# Format: ip|threat_type\n")
    if not os.path.exists(IOC_JA3_FILE):
        with open(IOC_JA3_FILE, "w") as f:
            f.write("# Format: ja3_md5|threat_type\n")
    if not os.path.exists(IOC_CERTS_FILE):
        with open(IOC_CERTS_FILE, "w") as f:
            f.write("# Format: cert_fingerprint|threat_type\n")
    if not os.path.exists(KEYWORD_FILE):
        # File extensions are matched as a whole extension (re:\.ext\b): .js does not match .json,
        # .doc does not match .docx and .log does not match .login.
        ext_sections = [
            ("System and executables", [
                ("exe", "Windows executable"),
                ("msi", "Windows installer package"),
                ("iso", "optical disc image"),
                ("dll", "Windows dynamic-link library"),
                ("sys", "Windows system file"),
                ("log", "system or application log"),
            ]),
            ("Code and development", [
                ("html", "HyperText Markup Language (web page)"),
                ("css", "Cascading Style Sheets (web design)"),
                ("js", "JavaScript script"),
                ("py", "Python script"),
                ("json", "JavaScript Object Notation data"),
                ("xml", "Extensible Markup Language"),
                ("php", "Hypertext Preprocessor script"),
                ("sh", "Bash / shell script (Linux)"),
                ("ps1", "PowerShell script (Windows)"),
                ("sql", "SQL database query file"),
            ]),
            ("Archives and compression", [
                ("zip", "standard compressed archive"),
                ("rar", "WinRAR compressed archive"),
                ("7z", "7-Zip high-compression archive"),
                ("tar", "file archive (Unix/Linux)"),
                ("gz", "Gzip compressed archive (Unix/Linux)"),
            ]),
            ("Documents and text", [
                ("pdf", "Portable Document Format (Adobe)"),
                ("docx", "Microsoft Word document (modern)"),
                ("doc", "Microsoft Word document (legacy)"),
                ("xlsx", "Microsoft Excel spreadsheet (modern)"),
                ("xls", "Microsoft Excel spreadsheet (legacy)"),
                ("pptx", "Microsoft PowerPoint presentation (modern)"),
                ("ppt", "Microsoft PowerPoint presentation (legacy)"),
                ("txt", "plain text file"),
                ("csv", "comma-separated values"),
                ("odt", "OpenDocument text (LibreOffice)"),
                ("ods", "OpenDocument spreadsheet (LibreOffice)"),
                ("rtf", "Rich Text Format"),
            ]),
            ("Images and graphics", [
                ("jpg", "compressed image (JPEG)"),
                ("jpeg", "compressed image (JPEG)"),
                ("png", "image with transparency (Portable Network Graphics)"),
                ("gif", "animated or simple graphic"),
                ("svg", "vector image (Scalable Vector Graphics)"),
                ("webp", "modern web image format"),
                ("bmp", "uncompressed bitmap image"),
                ("ico", "application icon or web favicon"),
                ("psd", "Adobe Photoshop project file"),
            ]),
        ]
        default_keywords = [
            "# Plain keywords (case-insensitive) or regexes prefixed with re:",
            "# They are searched in path/name/prev_name of smb_files.log only.",
            "# Text after two spaces and a # is a comment.",
            "# --- Active Directory & system ---",
            "ntds.dit", "re:\\bSAM\\b", "re:\\bSECURITY\\b", "re:\\bSYSTEM\\b", "shadow", ".dit", "hive",
            "# --- Secrets & credentials ---",
            "id_rsa", "id_dsa", "authorized_keys", "passwd", "password",
            "credential", "secret", "token", "api_key", ".env", "web.config",
            "# --- Backups ---",
            "backup", ".bak", ".old", "dump",
            "# --- Misc ---",
            "confidential", "internal", "# audit",
        ]
        for title, items in ext_sections:
            default_keywords.append(f"# --- {title} ---")
            default_keywords += [f"re:\\.{ext}\\b".ljust(16) + f"  # .{ext}: {desc}" for ext, desc in items]
        with open(KEYWORD_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(default_keywords) + "\n")


def _read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def load_domain_whitelist():
    return {l.lower() for l in _read_lines(WHITELIST_FILE)}


_INLINE_COMMENT_RE = re.compile(r"\s{2,}#.*$")


def load_keywords():
    """keywords.txt lines; text after two spaces and a # is an inline comment."""
    return [k for k in (_INLINE_COMMENT_RE.sub("", l).strip() for l in _read_lines(KEYWORD_FILE)) if k]


def load_ioc_database(file_path):
    iocs = {}
    for line in _read_lines(file_path):
        parts = line.split("|", 1)
        iocs[parts[0].strip().lower()] = parts[1].strip() if len(parts) > 1 else "malicious"
    return iocs


def get_ioc_domains():
    return load_ioc_database(IOC_DOMAINS_FILE)


def get_ioc_ips():
    return load_ioc_database(IOC_IPS_FILE)


# --- IP whitelist: all ip_whitelist*.txt files, merged ranges + binary search ---
_WL_EXACT = set()
_WL_RANGES = {4: ([], []), 6: ([], [])}


def reload_ip_whitelist():
    global _WL_EXACT, _WL_RANGES
    nets = {4: [], 6: []}
    exact = set()
    for path in sorted(glob.glob("ip_whitelist*.txt")):
        for line in _read_lines(path):
            try:
                if "/" in line:
                    n = ipaddress.ip_network(line, strict=False)
                    nets[n.version].append(n)
                else:
                    exact.add(ipaddress.ip_address(line))
            except ValueError:
                continue
    ranges = {}
    for v in (4, 6):
        merged = list(ipaddress.collapse_addresses(nets[v]))
        ranges[v] = ([int(n.network_address) for n in merged], [int(n.broadcast_address) for n in merged])
    _WL_EXACT, _WL_RANGES = exact, ranges
    is_ip_whitelisted.cache_clear()


@lru_cache(maxsize=262144)
def is_ip_whitelisted(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip in _WL_EXACT:
        return True
    starts, ends = _WL_RANGES[ip.version]
    v = int(ip)
    i = bisect.bisect_right(starts, v) - 1
    return i >= 0 and v <= ends[i]


# ======================================================================
# LOG INDEX + PARSER
# ======================================================================
def build_index(root):
    """Single walk of the tree -> {log_type: [paths sorted by decreasing size]}."""
    idx = defaultdict(list)
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                            continue
                        m = _LOG_NAME_RE.fullmatch(e.name)
                        if m:
                            size = e.stat().st_size
                            if size:
                                idx[m.group("kind")].append((size, e.path))
                    except OSError:
                        continue
        except OSError:
            continue
    return {k: [p for _, p in sorted(v, reverse=True)] for k, v in idx.items()}


def get_index(force=False):
    global _FILE_INDEX
    if _FILE_INDEX is None or force:
        print(f"[*] Indexing {LOG_ROOT} ...")
        _FILE_INDEX = build_index(LOG_ROOT)
        resume = ", ".join(f"{k}:{len(v)}" for k, v in sorted(_FILE_INDEX.items()))
        print(f"[+] {sum(len(v) for v in _FILE_INDEX.values())} log files ({resume or 'none'})")
    return _FILE_INDEX


def find_logs(kind):
    return get_index().get(kind, [])


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore", newline="")
    return open(path, "r", encoding="utf-8", errors="ignore", buffering=1 << 20, newline="")


def _s(v):
    if v is None:
        return "-"
    if isinstance(v, list):
        return ",".join(map(str, v))
    return str(v)


def iter_zeek(path, columns=None):
    """Iterates over a Zeek log (TSV or JSON, .gz accepted). `columns` limits the fields built (saves CPU)."""
    fields, idx = None, None
    try:
        with open_log(path) as f:
            for line in f:
                c = line[0]
                if c == "#":
                    if line.startswith("#fields"):  # may repeat in a concatenated file
                        fields = line.rstrip("\r\n").split("\t")[1:]
                        wanted = columns if columns else fields
                        idx = [(n, fields.index(n)) for n in wanted if n in fields]
                    continue
                if c == "{":
                    try:
                        d = json.loads(line)
                    except ValueError:
                        continue
                    yield {k: _s(d.get(k)) for k in (columns or d.keys()) if k in d}
                    continue
                if fields is None:
                    continue
                v = line.rstrip("\r\n").split("\t")
                if len(v) != len(fields):
                    continue
                yield {n: v[i] for n, i in idx}
    except (OSError, EOFError, zlib.error, ValueError) as e:
        sys.stderr.write(f"\n[!] Read interrupted on {path}: {e}\n")


# ======================================================================
# UTILITAIRES
# ======================================================================
@lru_cache(maxsize=262144)
def ip_class(ip_str):
    """private | public | special (multicast/broadcast/unspecified) | invalid"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"
    if ip.is_multicast or ip.is_unspecified or ip_str == "255.255.255.255":
        return "special"
    return "public" if ip.is_global else "private"


def is_private_ip(ip_str):
    return ip_class(ip_str) == "private"


def classify_flow(o, r):
    co, cr = ip_class(o), ip_class(r)
    if co in ("special", "invalid") or cr in ("special", "invalid"):
        return None
    if co == "private" and cr == "private":
        return "int"
    if co == "private":
        return "out"
    if cr == "private":
        return "in"
    return "ext"


def strip_port(host):
    if host.startswith("["):
        return host[1:].split("]")[0]
    if host.count(":") == 1:
        return host.split(":")[0]
    return host


def match_host(host, table):
    """Returns the `table` entry (dict/set) matching `host` or one of its parent domains.
    'microsoft.com' matches 'x.microsoft.com' but NOT 'microsoft.com.evil.ru'."""
    if not host or not table:
        return None
    if ":" in host or _IPV4_RE.fullmatch(host):
        return host if host in table else None
    labels = host.rstrip(".").split(".")
    for i in range(max(1, len(labels) - 1)):
        cand = ".".join(labels[i:])
        if cand in table:
            return cand
    return None


def display_url(host, uri):
    """Readable URL: plain path, absolute URL (proxy) or CONNECT request (uri = host:port)."""
    if uri.startswith("/"):
        return f"http://{host}{uri}"
    if uri.startswith(("http://", "https://")):
        return uri
    if uri in UNSET:
        return f"http://{host}/"
    return f"CONNECT {uri}"


def defang(url):
    """Non-clickable URL for display (hxxp, [.]); CSV exports keep the raw URL."""
    u = re.sub(r"^http", "hxxp", url, flags=re.I)
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    return u.replace(host, host.replace(".", "[.]"), 1) if host else u


def cut(s, n):
    s = s or ""
    return s if len(s) <= n else s[:n - 1] + "…"


def to_float(s, default=0.0):
    try:
        return float(s)
    except (TypeError, ValueError):
        return default


def format_ts(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except (TypeError, ValueError, OSError, OverflowError):
        return str(ts)


_TS_CELL_RE = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\dZ")


def csv_cell(v):
    """UTC time written as '... UTC' in CSV files: spreadsheets keep it as is instead of converting it to the
    local time zone (e.g. 23:15:00Z shown as 00:15:00 the next day in Paris in winter)."""
    return v[:-1] + " UTC" if isinstance(v, str) and _TS_CELL_RE.fullmatch(v) else v


def fmt_mail_date(s):
    """Date: header in the sender's time zone, normalized: 'Wed, 01 May 2024 10:15:00 -0500'
    -> '2024-05-01 10:15:00 -0500'. Raw value if it cannot be parsed."""
    try:
        dt = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        return s
    return dt.strftime("%Y-%m-%d %H:%M:%S %z") if dt and dt.tzinfo else s


def fmt_delay(sec):
    if sec < 0:
        return "(just before receipt)"
    if sec < 60:
        return f"+{sec:.0f}s"
    if sec < 3600:
        return f"+{sec / 60:.0f} min"
    if sec < 86400:
        return f"+{sec / 3600:.1f} h"
    return f"+{sec / 86400:.1f} d"


def fmt_bytes(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def shannon(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


_SUSPICIOUS_UA = re.compile(
    r"\b(curl|wget|python|powershell|wscript|cscript|certutil|bitsadmin|sqlmap|nmap|zgrab|"
    r"masscan|nikto|go-http-client|libwww-perl|java|bot)\b", re.I)
_SAFE_MS_UA = re.compile(
    r"\b(ariasdk|bits|ncsi|cryptoapi|delivery-optimization|wns|oneauth|windows-update-agent)\b", re.I)


def parse_os_and_status_from_ua(ua_string):
    ua = ua_string.lower()
    if _SUSPICIOUS_UA.search(ua):
        return "Tool / threat detected", "Suspicious"
    if _SAFE_MS_UA.search(ua):
        return "System service (Microsoft)", "Normal"
    if "windows nt" in ua:
        for tag, name in (("nt 10.0", "Windows 10/11"), ("nt 6.3", "Windows 8.1"),
                          ("nt 6.2", "Windows 8"), ("nt 6.1", "Windows 7")):
            if tag in ua:
                return name, "Normal"
        return "Windows (other)", "Normal"
    if "android" in ua:
        return "Android", "Normal"
    if "iphone" in ua or "ipad" in ua:
        return "iOS", "Normal"
    if "mac os x" in ua:
        return "macOS", "Normal"
    if "linux" in ua:
        return "Linux", "Normal"
    return "Unknown / other", "To investigate"


# ======================================================================
# PARALLELISM
# ======================================================================
def compile_keywords(kws):
    parts = [k[3:] if k.startswith("re:") else re.escape(k) for k in kws]
    return re.compile("|".join(parts), re.I) if parts else None


def _init_worker(ctx):
    global CTX
    CTX = dict(ctx)
    if "kw" in CTX:
        CTX["kw_re"] = compile_keywords(CTX["kw"])
    if "exts" in CTX:
        CTX["ext_re"] = re.compile(
            "(?:" + "|".join(re.escape(e) for e in CTX["exts"]) + ")(?=$|[?&#;/])", re.I)


def _progress(n, total):
    if total > 1 and sys.stderr.isatty():
        sys.stderr.write(f"\r    {n}/{total} files processed")
        sys.stderr.flush()


def run_parallel(func, items, ctx):
    items = list(items)
    if not items:
        return []
    results, total = [], len(items)
    if JOBS <= 1 or total == 1:
        _init_worker(ctx)
        for n, it in enumerate(items, 1):
            results.append(func(it))
            _progress(n, total)
    else:
        with ProcessPoolExecutor(max_workers=min(JOBS, total), initializer=_init_worker,
                                 initargs=(ctx,)) as ex:
            futs = [ex.submit(func, it) for it in items]
            for n, fut in enumerate(as_completed(futs), 1):
                results.append(fut.result())
                _progress(n, total)
    if total > 1 and sys.stderr.isatty():
        sys.stderr.write("\n")
    return results


def build_ctx(**extra):
    ioc_ips, ioc_dom = get_ioc_ips(), get_ioc_domains()
    ctx = {"ioc_ips": ioc_ips, "ioc_hosts": {**ioc_ips, **ioc_dom}, "dom_wl": load_domain_whitelist()}
    ctx.update(extra)
    return ctx


# ======================================================================
# RAPPORT / FINDINGS
# ======================================================================
def reset_findings(phase):
    FINDINGS[:] = [f for f in FINDINGS if f["phase"] != phase]


def add_finding(phase, severity, src, dst, kind, detail, ts="", log="", uid=""):
    FINDINGS.append({"phase": phase, "severity": severity, "src": src, "dst": dst,
                     "type": kind, "detail": detail, "first_seen": ts, "log": log, "uid": uid})


def title(txt):
    print(f"\n[*] --- {txt} ---")


def print_host_scores(top=15):
    w = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}
    score, kinds = Counter(), defaultdict(set)
    for f in FINDINGS:
        if f["src"] and is_private_ip(f["src"]):
            score[f["src"]] += w.get(f["severity"], 0)
            kinds[f["src"]].add(f["type"])
    if top:
        print("\n" + "=" * 60 + "\n INTERNAL HOST SCORE (weighted sum of findings)\n" + "=" * 60)
    # Single pass over the findings (instead of a full pass per host)
    sevs, phases = defaultdict(Counter), defaultdict(set)
    for f in FINDINGS:
        if f["src"] in score:
            sevs[f["src"]][f["severity"]] += 1
            phases[f["src"]].add(f["phase"])
    rows = []
    for ip, s in score.most_common():
        sev = sevs[ip]
        rows.append([ip, s, sev.get("critical", 0), sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0),
                     " ".join(sorted(phases[ip])), ", ".join(sorted(kinds[ip]))])
    if not score:
        if top:
            print("[-] No finding attached to an internal host.")
        return rows
    for ip, s in score.most_common(top):
        print(f"  {ip:<15} score={s:<4} {', '.join(sorted(kinds[ip]))}")
    return rows


def export_findings(out_dir, host_rows=None):
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if host_rows is None:
        host_rows = print_host_scores(top=0)
    p_hosts = os.path.join(out_dir, f"host_scores_{stamp}.csv")
    with open(p_hosts, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "score", "critical", "high", "medium", "low", "phases", "finding_types"])
        w.writerows(host_rows)
    p_sum = os.path.join(out_dir, f"summary_{stamp}.txt")
    by_phase = Counter(f["phase"] for f in FINDINGS)
    by_sev = Counter(f["severity"] for f in FINDINGS)
    by_type = Counter(f["type"] for f in FINDINGS)
    with open(p_sum, "w", encoding="utf-8") as f:
        f.write(f"Zeek Forensics Hunter v{VERSION} - {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Log root: {LOG_ROOT}\n")
        f.write(f"Findings: {len(FINDINGS)}\n")
        f.write("By severity: " + ", ".join(f"{k}={by_sev.get(k, 0)}"
                                             for k in ("critical", "high", "medium", "low", "info")) + "\n")
        f.write("By phase   : " + ", ".join(f"{k}={v}" for k, v in sorted(by_phase.items())) + "\n")
        f.write("By type    : " + ", ".join(f"{k}={v}" for k, v in by_type.most_common()) + "\n\n")
        f.write("Top 15 internal hosts (weighted score critical=5, high=3, medium=2, low=1):\n")
        for ip, sc, c, h, m, l, ph, kinds in host_rows[:15]:
            f.write(f"  {ip:<15} score={sc:<4} critical={c} high={h} medium={m} low={l} phases={ph} | {kinds}\n")
        f.write("\nCRITICAL / HIGH findings:\n")
        for x in sorted((x for x in FINDINGS if x["severity"] in ("critical", "high")),
                        key=lambda x: (x["severity"] != "critical", x["first_seen"] or "~")):
            f.write(f"  [{x['phase']}] {x['severity'].upper():<8} {x['first_seen'] or '-':<20} {x['src']} -> {x['dst']} {x['type']} : "
                    f"{x['detail'][:200]}{' uid=' + x['uid'] if x['uid'] else ''}\n")
    cols = ["phase", "severity", "src", "dst", "type", "detail", "first_seen", "log", "uid"]
    p_csv = os.path.join(out_dir, f"findings_{stamp}.csv")
    with open(p_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows({k: csv_cell(v) for k, v in x.items()} for x in FINDINGS)
    p_json = os.path.join(out_dir, f"findings_{stamp}.json")
    with open(p_json, "w", encoding="utf-8") as f:
        json.dump(FINDINGS, f, ensure_ascii=False, indent=1)
    print(f"[+] Export : {p_csv}, {p_json} ({len(FINDINGS)} findings), {p_hosts}, {p_sum}")


# ======================================================================
# WORKERS (module-level functions so they can be pickled)
# ======================================================================
CONN_COLS = ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "service",
             "orig_bytes", "resp_bytes", "conn_state"]
HTTP_COLS = ["ts", "uid", "id.orig_h", "id.resp_h", "host", "uri", "user_agent", "resp_mime_types"]
DNS_COLS = ["ts", "id.orig_h", "query", "qtype_name", "rcode_name"]
SMB_COLS = ["ts", "uid", "id.orig_h", "id.resp_h", "action", "path", "name", "prev_name"]
DOMAIN_FIELD = {"http": "host", "dns": "query", "ssl": "server_name"}


# --- Timestamp sampling for beaconing ---
# Sample = [step, timestamps, total count, first ts, last ts]. One timestamp out of `step` is kept; when the
# list reaches MAX_BEACON_TS, every other one is dropped and the step doubles. The sample therefore covers the
# whole period (not just the start), and a periodic series stays periodic (interval = step x period).
def ts_new(ts):
    return [1, [ts], 1, ts, ts]


def ts_add(s, ts):
    if s[2] % s[0] == 0:
        s[1].append(ts)
        if len(s[1]) >= MAX_BEACON_TS:
            s[1] = s[1][::2]
            s[0] *= 2
    s[2] += 1
    if ts < s[3]:
        s[3] = ts
    if ts > s[4]:
        s[4] = ts


def ts_merge(a, b):
    """Merges two samples (steps are powers of 2): both are brought down to the larger step."""
    if a is None:
        return b
    step = max(a[0], b[0])
    lst = sorted(a[1][::step // a[0]] + b[1][::step // b[0]])
    while len(lst) > 4 * MAX_BEACON_TS:
        lst = lst[::2]
        step *= 2
    return [step, lst, a[2] + b[2], min(a[3], b[3]), max(a[4], b[4])]


def task_conn(path):
    flows, times, fails = {}, {}, defaultdict(set)
    for row in iter_zeek(path, CONN_COLS):
        o, r = row.get("id.orig_h"), row.get("id.resp_h")
        if not o or not r:
            continue
        p = row.get("id.resp_p", "0")
        ts = to_float(row.get("ts"))
        ob, rb = row.get("orig_bytes", "0"), row.get("resp_bytes", "0")
        ob = int(ob) if ob.isdigit() else 0
        rb = int(rb) if rb.isdigit() else 0
        k = (o, r, p, row.get("proto", "-"), row.get("service", "-"))
        f = flows.get(k)
        if f is None:
            flows[k] = [1, ob, rb, ts, ts, path]
        else:
            f[0] += 1
            f[1] += ob
            f[2] += rb
            if ts < f[3]:
                f[3], f[5] = ts, path
            if ts > f[4]:
                f[4] = ts
        if row.get("conn_state") in FAIL_STATES:
            fails[o].add((r, p))
        if p not in ("53", "123") and ip_class(o) == "private" and ip_class(r) == "public":
            s = times.get((o, r, p))
            if s is None:
                times[(o, r, p)] = ts_new(ts)
            else:
                ts_add(s, ts)
    return flows, times, dict(fails)


def merge_conn(results):
    flows, times, fails = {}, {}, defaultdict(set)
    for f, t, fl in results:
        for k, v in f.items():
            cur = flows.get(k)
            if cur is None:
                flows[k] = v
            else:
                cur[0] += v[0]
                cur[1] += v[1]
                cur[2] += v[2]
                if v[3] < cur[3]:
                    cur[3], cur[5] = v[3], v[5]
                cur[4] = max(cur[4], v[4])
        for k, v in t.items():
            times[k] = ts_merge(times.get(k), v)
        for k, v in fl.items():
            fails[k] |= v
    return flows, times, fails


def get_conn_data(force=False):
    global _CONN_CACHE
    if _CONN_CACHE is None or force:
        files = find_logs("conn")
        if not files:
            print("[!] No conn.log found.")
            return None
        print(f"[*] Reading {len(files)} conn.log (single pass, result cached)...")
        _CONN_CACHE = merge_conn(run_parallel(task_conn, files, {}))
    return _CONN_CACHE


def task_domains(item):
    """http (host) / dns (query) / ssl (server_name): IOCs + User-Agent collection."""
    kind, path = item
    field = DOMAIN_FIELD[kind]
    cols = ["ts", "uid", "id.orig_h", "id.resp_h", field] + (["uri", "user_agent"] if kind == "http" else [])
    iocs = CTX["ioc_hosts"]
    alerts, uas = {}, Counter()
    for row in iter_zeek(path, cols):
        o = row.get("id.orig_h", "")
        if kind == "http":
            ua = row.get("user_agent", "-")
            if ua not in UNSET:
                uas[(o, ua)] += 1
        name = row.get(field, "-")
        if name in UNSET:
            continue
        host = strip_port(name.lower()) if kind == "http" else name.lower().rstrip(".")
        hit = match_host(host, iocs)
        if hit is None:
            continue
        # DNS/TLS: aggregated per IOC domain (avoids a flood of alerts per subdomain)
        key = (kind, o, row.get("id.resp_h", "") if kind == "http" else "", host if kind == "http" else hit, hit,
               row.get("uri", "") if kind == "http" else "")
        ts = to_float(row.get("ts"))
        a = alerts.get(key)
        if a is None:
            alerts[key] = [1, ts, ts, row.get("uid", ""), path]  # count, first seen, last seen, first uid, first log
        else:
            a[0] += 1
            if ts < a[1]:
                a[1], a[3], a[4] = ts, row.get("uid", ""), path
            a[2] = max(a[2], ts)
    return alerts, uas


def task_http_dl(path):
    ext_re, wl, iocs, ioc_ips = CTX["ext_re"], CTX["dom_wl"], CTX["ioc_hosts"], CTX["ioc_ips"]
    out = {}
    for row in iter_zeek(path, HTTP_COLS):
        host = strip_port(row.get("host", "-").lower())
        if host in UNSET:
            continue
        hit = match_host(host, iocs)
        if not hit and match_host(host, wl):  # an explicit IOC overrides the domain whitelist
            continue
        uri, mime = row.get("uri", ""), row.get("resp_mime_types", "")
        by_ext = ext_re.search(uri) is not None
        by_mime = any(m in mime for m in PE_MIMES)
        if not (by_ext or by_mime):
            continue
        resp = row.get("id.resp_h", "")
        threat = iocs[hit] if hit else ioc_ips.get(resp)
        key = (row.get("id.orig_h", ""), resp, host, uri, threat, "ext" if by_ext else "mime-PE", path)
        ts = to_float(row.get("ts"))
        a = out.get(key)
        if a is None:
            out[key] = [1, ts, row.get("uid", "")]
        else:
            a[0] += 1
            a[1] = min(a[1], ts)
    return out


def task_smb(path):
    rx, out = CTX["kw_re"], {}
    for row in iter_zeek(path, SMB_COLS):
        text = " ".join(x for x in (row.get("path", "-"), row.get("name", "-"), row.get("prev_name", "-"))
                        if x not in UNSET)
        m = rx.search(text)
        if not m:
            continue
        key = (row.get("id.orig_h", ""), row.get("id.resp_h", ""), row.get("action", "-"),
               text, m.group(0).lower(), path)
        ts = to_float(row.get("ts"))
        a = out.get(key)
        if a is None:
            out[key] = [1, ts, row.get("uid", "")]
        else:
            a[0] += 1
            a[1] = min(a[1], ts)
    return out


def task_dns(path):
    wl = CTX["dom_wl"]
    subs, nx, ent, txt = defaultdict(set), Counter(), {}, Counter()
    for row in iter_zeek(path, DNS_COLS):
        q = row.get("query", "-").lower().rstrip(".")
        if q in UNSET or q.endswith((".arpa", ".local")) or match_host(q, wl):
            continue
        labels = q.split(".")
        if len(labels) < 2:
            continue
        o, base = row.get("id.orig_h", ""), ".".join(labels[-2:])
        if row.get("rcode_name") == "NXDOMAIN":
            nx[o] += 1
        if row.get("qtype_name") in ("TXT", "NULL"):
            txt[(o, base)] += 1
        if len(labels) > 2:
            s = subs[(o, base)]
            if len(s) < 20000:
                s.add(".".join(labels[:-2]))
        first = labels[0]
        if len(first) >= DNS_LABEL_MIN:
            e = shannon(first)
            if e >= DNS_ENTROPY:
                cur = ent.get((o, base))
                if cur is None:
                    ent[(o, base)] = [1, q, e, to_float(row.get("ts"))]
                else:
                    cur[0] += 1
                    cur[2] = max(cur[2], e)
    return dict(subs), nx, ent, txt


# ======================================================================
# PHASES
# ======================================================================
def _ip_key(ip):
    a = ipaddress.ip_address(ip)
    return a.version, a


def phase0_cartography(top=None):
    title("PHASE 0: Network mapping (IP inventory, then grouped flows)")
    data = get_conn_data()
    if not data:
        return
    top = top or TOP_PUBLIC_IPS
    pairs = defaultdict(lambda: [0, 0])
    for (o, r, *_), (n, ob, rb, *_rest) in data[0].items():
        a = pairs[(o, r)]
        a[0] += n
        a[1] += ob + rb
    private, all_public = set(), set()
    public = {}  # non-whitelisted public IP -> [conn count, volume, peers]
    grouped, ignored, special = defaultdict(Counter), 0, 0
    for (o, r), (n, vol) in pairs.items():
        kind = classify_flow(o, r)
        if kind is None:
            special += 1
            continue
        for ip, peer in ((o, r), (r, o)):
            if ip_class(ip) == "private":
                private.add(ip)
                continue
            all_public.add(ip)
            if not is_ip_whitelisted(ip):
                s = public.setdefault(ip, [0, 0, set()])
                s[0] += n
                s[1] += vol
                s[2].add(peer)
        if kind == "out":
            src, dst, dt, dpub, label = o, r, "Public", r, r
        elif kind == "in":
            src, dst, dt, dpub, label = r, o, "Public", o, f"{o} (entrant)"
        elif kind == "int":
            src, dst, dt, dpub, label = o, r, "Private", None, r
        else:
            src, dst, dt, dpub, label = o, r, "Public", None, r
        if dpub and is_ip_whitelisted(dpub):
            ignored += 1
            continue
        grouped[(src, dt)][label] += n

    # --- 1. IP inventory ---
    print("\n" + "=" * 100 + "\n 1. IP INVENTORY\n" + "=" * 100)
    print(f"\n-> Private IPs ({len(private)}):")
    if private:
        print(textwrap.fill(", ".join(sorted(private, key=_ip_key)), width=100,
                            initial_indent="   ", subsequent_indent="   "))
    else:
        print("   None")

    ranked = sorted(public.items(), key=lambda x: (-x[1][0], -x[1][1]))
    print(f"\n-> Non-whitelisted public IPs: {len(public)} (out of {len(all_public)} seen, "
          f"{len(all_public) - len(public)} whitelisted); top {min(top, len(ranked))} by connection count")
    if ranked:
        print(f"   {'Public IP':<39} {'Conn.':>7} {'Volume':>10} {'Peers':>5}  Sample peers")
        print("   " + "-" * 96)
        for ip, (n, vol, peers) in ranked[:top]:
            ex = ", ".join(sorted(peers, key=_ip_key)[:3]) + (" ..." if len(peers) > 3 else "")
            print(f"   {ip:<39} {n:>7} {fmt_bytes(vol):>10} {len(peers):>5}  {ex}")
        if len(ranked) > top:
            print(f"   ... {len(ranked) - top} more public IP(s): full list in the export (--out).")
    else:
        print("   None")
    write_table("public_ips", ["ip", "connections", "bytes", "peer_count", "peers"],
                [[ip, n, vol, len(peers), " ".join(sorted(peers, key=_ip_key))] for ip, (n, vol, peers) in ranked])

    # --- 2. Communications ---
    print("\n" + "=" * 100 + "\n 2. COMMUNICATIONS (flows grouped by source, destinations sorted by connection count)\n"
          + "=" * 100)
    print(f"   {ignored} pair(s) hidden by the IP whitelist, {special} multicast/broadcast pair(s) ignored; "
          f"max {top} destinations per line\n")
    if not grouped:
        print("   No flows.")
    for (src, dt), dests in sorted(grouped.items(), key=lambda x: (_ip_key(x[0][0]), x[0][1])):
        stype = "Private" if is_private_ip(src) else "Public"
        ordered = [d for d, _ in dests.most_common()]
        more = f" (+{len(ordered) - top} more)" if len(ordered) > top else ""
        print(f"  [{stype} > {dt}] {src:<15} ---> {', '.join(ordered[:top])}{more}")


def print_ioc_domains(phase, alerts, ioc_hosts, compromised):
    """Summary view: one line per IOC domain (per-protocol counters + time range),
    then one line per source (protocols, first -> last seen, uid, sample URL)."""
    labels = {"dns": "DNS", "http": "HTTP", "ssl": "TLS"}
    doms, rows = {}, []
    for (kind, o, r, host, hit, uri), (n, first, last, uid, log) in alerts.items():
        d = doms.get(hit)
        if d is None:
            d = doms[hit] = {"n": Counter(), "first": first, "last": last, "src": {}, "hosts": set()}
        d["n"][kind] += n
        d["first"], d["last"] = min(d["first"], first), max(d["last"], last)
        if host != hit:
            d["hosts"].add(host)
        s = d["src"].get(o)
        if s is None:
            s = d["src"][o] = {"n": Counter(), "first": first, "last": last, "uid": uid, "log": log,
                               "dst": set(), "ex": "", "ex_ts": 0.0}
        s["n"][kind] += n
        if first < s["first"]:
            s["first"], s["uid"], s["log"] = first, uid, log
        s["last"] = max(s["last"], last)
        if r:
            s["dst"].add(r)
        if kind == "http" and (not s["ex"] or first < s["ex_ts"]):
            s["ex"], s["ex_ts"] = display_url(host, uri), first
        rows.append([hit, ioc_hosts.get(hit, "malicious"), labels[kind], o, r, host,
                     display_url(host, uri) if kind == "http" else "", n, format_ts(first), format_ts(last), uid, log])

    n_src = len({o for d in doms.values() for o in d["src"]})
    n_evt = sum(sum(d["n"].values()) for d in doms.values())
    print(f"\n--- IOC DOMAINS / HOSTS (HTTP, DNS, TLS SNI): {len(doms)} domain(s), {n_src} source(s), "
          f"{n_evt} event(s); sorted by first seen ---")
    if not doms:
        print("[-] No traffic to a known IOC domain.")
        return
    print(f" {'IOC domain':<34} {'Threat':<20} {'Src':>4} {'DNS':>6} {'HTTP':>6} {'TLS':>6}  "
          f"{'First seen':<20} {'Last seen':<20}")
    print(" " + "-" * 124)
    for hit, d in sorted(doms.items(), key=lambda x: x[1]["first"]):
        threat = ioc_hosts.get(hit, "malicious")
        c = d["n"]
        print(f" {cut(hit, 34):<34} {cut(threat, 20):<20} {len(d['src']):>4} {c['dns'] or '-':>6} "
              f"{c['http'] or '-':>6} {c['ssl'] or '-':>6}  {format_ts(d['first']):<20} {format_ts(d['last']):<20}")
        if d["hosts"]:
            hs = sorted(d["hosts"])
            print(f"   HTTP hosts: {', '.join(cut(h, 40) for h in hs[:4])}{f' +{len(hs) - 4}' if len(hs) > 4 else ''}")
        srcs = sorted(d["src"].items(), key=lambda x: x[1]["first"])
        for o, s in srcs[:IOC_SRC_LIMIT]:
            proto = " ".join(f"{labels[k]}x{s['n'][k]}" for k in ("dns", "http", "ssl") if s["n"][k])
            dst = f" -> {', '.join(sorted(s['dst'])[:2])}" if s["dst"] else ""
            print(f"   ↳ {o:<15}{cut(dst, 22):<22} {proto:<24} {format_ts(s['first'])} -> {format_ts(s['last'])}"
                  f"  uid={s['uid'] or '-'}")
            if s["ex"]:
                print(f"     {'':<37} e.g.: {defang(cut(s['ex'], 90))}")
        if len(srcs) > IOC_SRC_LIMIT:
            print(f"   ↳ ... +{len(srcs) - IOC_SRC_LIMIT} more source(s) in the export (--out)")
        # One finding per (IOC domain, source) with the time range, instead of one per URL
        for o, s in srcs:
            kinds = [k for k in ("dns", "http", "ssl") if s["n"][k]]
            if is_private_ip(o):
                compromised[o].add("IOC " + "/".join(labels[k] for k in kinds))
            proto = " ".join("%sx%d" % (labels[k], s["n"][k]) for k in kinds)
            ex = " e.g.=" + s["ex"] if s["ex"] else ""
            detail = f"{threat} {hit} {proto} {format_ts(s['first'])} -> {format_ts(s['last'])}{ex}"
            add_finding(phase, "high", o, ",".join(sorted(s["dst"])[:3]), "ioc_domain", detail,
                        format_ts(s["first"]), s["log"], s["uid"])
    write_table("ioc_domains", ["ioc_domain", "threat", "proto", "src_ip", "dst_ip", "host", "url", "count",
                                 "premier_vu", "dernier_vu", "uid", "log"],
                sorted(rows, key=lambda x: (x[0], x[8])))


def phase1_discovery():
    phase = "1"
    reset_findings(phase)
    title("PHASE 1: Discovery & threat intel (IOC IPs / domains / DNS / SNI / User-Agents)")
    data = get_conn_data()
    if not data:
        return
    flows = data[0]
    ctx = build_ctx()
    ioc_ips, ioc_hosts = ctx["ioc_ips"], ctx["ioc_hosts"]
    compromised = defaultdict(set)

    # --- IOC IPs (an explicit IOC overrides the IP whitelist) ---
    print("\n--- FLOWS TO IOC IPs ---")
    agg = {}
    for (o, r, p, proto, svc), (n, ob, rb, first, last, log) in flows.items():
        kind = classify_flow(o, r)
        if kind not in ("out", "in"):
            continue
        src, pub = (o, r) if kind == "out" else (r, o)
        if pub in ioc_ips:
            a = agg.get((src, pub, p, proto, kind))
            if a is None:
                agg[(src, pub, p, proto, kind)] = [n, first, log]
            else:
                a[0] += n
                if first < a[1]:
                    a[1], a[2] = first, log
    hits = [(src, pub, p, proto, n, first, log, ioc_ips[pub], kind)
            for (src, pub, p, proto, kind), (n, first, log) in agg.items()]
    if hits:
        for src, pub, p, proto, n, first, log, threat, kind in sorted(hits):
            arrow = "--->" if kind == "out" else "<---"
            print(f"  [!] [IP IOC MATCH] {src} {arrow} {pub}:{p}/{proto} x{n} (threat: {threat}) "
                  f"[{format_ts(first)}, {log}]")
            compromised[src].add("IP IOC")
            add_finding(phase, "high", src, pub, "ioc_ip", f"{threat} port {p}/{proto} x{n}",
                        format_ts(first), log)
    else:
        print("[-] No flow to a known malicious IP.")

    # --- IOC domains: HTTP + DNS + TLS SNI, and User-Agent collection ---
    items = [(k, p) for k in ("http", "dns", "ssl") for p in find_logs(k)]
    results = run_parallel(task_domains, items, ctx)
    alerts, uas = {}, Counter()
    for a, u in results:
        uas.update(u)
        for k, v in a.items():  # merge across files: add up counts, keep first / last seen
            cur = alerts.get(k)
            if cur is None:
                alerts[k] = v
            else:
                cur[0] += v[0]
                if v[1] < cur[1]:
                    cur[1], cur[3], cur[4] = v[1], v[3], v[4]
                cur[2] = max(cur[2], v[2])
    print_ioc_domains(phase, alerts, ioc_hosts, compromised)

    # --- User-Agents (suspicious first, limited display) ---
    order = {"Suspicious": 0, "To investigate": 1, "Normal": 2}
    to_check, ua_rows = defaultdict(set), []
    for (o, ua), n in uas.items():
        os_name, status = parse_os_and_status_from_ua(ua)
        if status == "Suspicious" and is_private_ip(o):
            compromised[o].add("UA suspect")
            add_finding(phase, "medium", o, "", "ua_suspect", ua[:200])
        elif status == "To investigate" and is_private_ip(o):
            to_check[o].add(ua)
        ua_rows.append((order[status], o, os_name, status, n, ua))
    ua_rows.sort(key=lambda x: (x[0], -x[4], x[1]))
    print(f"\n--- USER-AGENTS & INFERRED OS ({len(ua_rows)} IP/UA pairs, suspicious first) ---")
    print(f"{'Source IP':<15} | {'Inferred OS':<28} | {'UA status':<15} | {'Count':>6} | User-Agent")
    print("-" * 110)
    for _, o, os_name, status, n, ua in ua_rows[:DISPLAY_LIMIT]:
        print(f"{o:<15} | {os_name:<28} | {status:<15} | {n:>6} | {cut(ua, 160)}")
    if len(ua_rows) > DISPLAY_LIMIT:
        print(f"  ... {len(ua_rows) - DISPLAY_LIMIT} more lines (lowest priority) in the export (--out).")
    write_table("user_agents", ["src_ip", "os", "status", "count", "user_agent"],
                [[o, os_name, status, n, ua] for _, o, os_name, status, n, ua in ua_rows])

    print("\n" + "=" * 60 + "\n SUMMARY: COMPROMISED / SUSPICIOUS PRIVATE IPs\n" + "=" * 60)
    if compromised:
        for ip in sorted(compromised, key=ipaddress.ip_address):
            print(f"  [!] {ip} : {', '.join(sorted(compromised[ip]))}")
    else:
        print("[-] No private IP compromised via IOC / suspicious UA.")
    rest = {ip: u for ip, u in to_check.items() if ip not in compromised}
    if rest:
        print("\n  [?] Hosts with an unknown User-Agent to investigate (unconfirmed):")
        for ip in sorted(rest, key=ipaddress.ip_address):
            print(f"      - {ip} ({len(rest[ip])} UA distincts)")


def phase2_spearphishing(exts=None):
    phase = "2"
    reset_findings(phase)
    title("PHASE 2: Spearphishing (suspicious emails + downloads)")
    http_files = find_logs("http")
    exts = exts or CLI_EXTS
    if exts is None and sys.stdin.isatty():
        raw = input(f"Targeted extensions [default: {'|'.join(DEFAULT_EXTS)}]: ").strip()
        exts = [e.strip() for e in raw.split("|") if e.strip()] if raw else None
    exts = exts or DEFAULT_EXTS

    # Emails first: the most likely entry point, and the most useful view
    email_triage(exts)

    title("HTTP DOWNLOADS (targeted extensions / executable MIME)")
    if not http_files:
        print("[!] No http.log found.")
        return
    merged = {}
    for r in run_parallel(task_http_dl, http_files, build_ctx(exts=exts)):
        merged.update(r)

    bad = {k: v for k, v in merged.items() if k[4]}
    sus = {k: v for k, v in merged.items() if not k[4]}

    print("\n--- DOWNLOAD ALERTS (confirmed IOC) ---")
    sources = set()
    if not bad:
        print("[-] No download matches known IOCs.")
    for (o, r, host, uri, threat, why, log), (n, ts, uid) in sorted(bad.items(), key=lambda x: x[1][1]):
        print(f"  [!] [MALICIOUS: {threat}] {format_ts(ts)} {o} ---> {r} : {defang(display_url(host, uri))} "
              f"x{n} uid={uid}")
        sources.add(o)
        add_finding(phase, "high", o, r, "dl_ioc", f"{threat} {display_url(host, uri)}", format_ts(ts), log, uid)
    if sources:
        print("[!] Compromised (private) source IPs: " + ", ".join(sorted(sources, key=ipaddress.ip_address)))

    # Per-host aggregated view: an unknown host serving executables to several workstations stands out at once
    by_host = {}
    rows = []
    for (o, r, host, uri, _, why, log), (n, ts, uid) in sus.items():
        h = by_host.get(host)
        if h is None:
            h = by_host[host] = [0, set(), set(), ts, 0, uri, uid, set()]
        h[0] += n
        h[1].add(o)
        h[2].add(uri)
        h[7].add(r)
        if why == "mime-PE":
            h[4] += 1
        if ts < h[3]:
            h[3], h[5], h[6] = ts, uri, uid
        rows.append([format_ts(ts), o, r, host, display_url(host, uri), why, n, uid, log])
        add_finding(phase, "medium" if why == "mime-PE" else "low", o, r, "dl_suspect",
                    f"{display_url(host, uri)} ({why})", format_ts(ts), log, uid)
    ordered = sorted(by_host.items(), key=lambda x: (-(x[1][4] > 0), -len(x[1][1]), x[1][3]))
    print(f"\n--- SUSPICIOUS DOWNLOADS (non-IOC): {len(sus)} distinct requests across {len(by_host)} hosts "
          f"(PE first, then number of workstations) ---")
    if ordered:
        print(f"  {'PE':<3} {'Host':<40} {'Req':>5} {'Files':>5} {'Hosts':>6}  {'First seen':<20} Sample / workstations")
        print("  " + "-" * 120)
    for host, (n, srcs, uris, first, pe, ex_uri, uid, dsts) in ordered[:20]:
        print(f"  {'[PE]' if pe else '    ':<3} {cut(host, 40):<40} {n:>5} {len(uris):>5} {len(srcs):>6}  "
              f"{format_ts(first):<20} {defang(cut(display_url(host, ex_uri), 70))}")
        print(f"  {'':<4}↳ workstations: {', '.join(sorted(srcs)[:6])}{' ...' if len(srcs) > 6 else ''} | uid={uid}")
    if len(ordered) > 20:
        print(f"  ... {len(ordered) - 20} more host(s) in the export (--out).")
    write_table("suspicious_downloads", ["ts", "src_ip", "dst_ip", "host", "url", "reason", "count", "uid", "log"],
                sorted(rows))


def beacon_stats(sample):
    """(total count, real median interval, regularity, first, last) if the series is periodic, else None.
    `sample` is a ts_new/ts_add/ts_merge sample: the measured interval is divided by the step."""
    step, ts, total, first, last = sample
    if total < BEACON_MIN_CONN or len(ts) < BEACON_MIN_CONN:
        return None
    ts = sorted(ts)
    d = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(d) < BEACON_MIN_CONN - 1:
        return None
    med = median(d)
    if med / step < 1:
        return None
    ratio = sum(1 for x in d if abs(x - med) <= BEACON_JITTER * med) / len(d)
    return (total, med / step, ratio, first, last) if ratio >= BEACON_RATIO else None


def detect_beacons(times):
    out = []
    for (o, r, p), sample in times.items():
        if is_ip_whitelisted(r):
            continue
        st = beacon_stats(sample)
        if st:
            n, med, ratio, first, last = st
            out.append((o, r, p, n, med, ratio, first, last))
    return sorted(out, key=lambda x: -x[3])


def phase3_c2(top=25):
    phase = "3"
    reset_findings(phase)
    title("PHASE 3: C2 traffic (non-standard ports & beaconing)")
    data = get_conn_data()
    if not data:
        return
    flows, times, _ = data

    agg = {}
    for (o, r, p, proto, svc), (n, ob, rb, first, last, log) in flows.items():
        if classify_flow(o, r) != "out" or not p.isdigit() or int(p) in STD_PORTS or is_ip_whitelisted(r):
            continue
        k = (o, r, p, proto)
        a = agg.get(k)
        if a is None:
            agg[k] = [n, ob, rb, first, last, svc, log]
        else:
            a[0] += n
            a[1] += ob
            a[2] += rb
            a[3] = min(a[3], first)
            a[4] = max(a[4], last)
    rows = sorted(agg.items(), key=lambda x: -x[1][0])
    print(f"\n--- NON-STANDARD PORTS to the outside ({len(rows)} triplets, top {top} by connection count) ---")
    print(f"{'Source IP':<15} | {'Dest IP':<15} | {'Port':<10} | {'Count':>6} | {'Sent':>9} | {'Received':>9} | Service")
    print("-" * 100)
    for (o, r, p, proto), (n, ob, rb, first, last, svc, log) in rows[:top]:
        print(f"{o:<15} | {r:<15} | {p + '/' + proto:<10} | {n:>6} | {fmt_bytes(ob):>9} | "
              f"{fmt_bytes(rb):>9} | {svc} [{format_ts(first)}, {log}]")
    for (o, r, p, proto), (n, ob, rb, first, last, svc, log) in rows:
        add_finding(phase, "low", o, r, "port_non_standard", f"{p}/{proto} x{n} svc={svc}", format_ts(first), log)

    beacons = detect_beacons(times)
    print(f"\n--- BEACONING (periodic connections, >={BEACON_MIN_CONN} conn., jitter ±{int(BEACON_JITTER * 100)}%): "
          f"{len(beacons)} candidate(s) ---")
    for o, r, p, n, med, ratio, first, last in beacons:
        print(f"  [!] {o} ---> {r}:{p} x{n} | median interval {med:.0f}s | regularity {ratio:.0%} "
              f"| {format_ts(first)} -> {format_ts(last)}")
        add_finding(phase, "high", o, r, "beaconing", f"port {p} x{n} median={med:.0f}s regularity={ratio:.0%}",
                    format_ts(first))
    print("[i] Behind an explicit proxy, this beaconing is not visible here: see phase 9 (http.log).")


def phase4_lateral_movement():
    phase = "4"
    reset_findings(phase)
    title("PHASE 4: Lateral movement (SMB/RDP/WinRM/RPC)")
    data = get_conn_data()
    if not data:
        return
    flows = data[0]
    internal, inbound = {}, {}
    for (o, r, p, proto, svc), (n, ob, rb, first, last, log) in flows.items():
        if not p.isdigit() or int(p) not in LATERAL_PORTS:
            continue
        kind = classify_flow(o, r)
        if kind == "int":
            tgt = internal
        elif kind == "in" and not is_ip_whitelisted(o):
            tgt = inbound
        else:
            continue
        k = (o, r, int(p))
        a = tgt.get(k)
        if a is None:
            tgt[k] = [n, first, last, log]
        else:
            a[0] += n
            a[1] = min(a[1], first)
            a[2] = max(a[2], last)

    print(f"\n--- FLUX INTERNES ({len(internal)} triplets) ---")
    fan = defaultdict(set)
    for i, ((o, r, p), (n, first, last, log)) in enumerate(sorted(internal.items(), key=lambda x: x[1][1])):
        if i < DISPLAY_LIMIT:
            print(f"  [+] {LATERAL_PORTS[p]:<9} {o} ---> {r} (port {p}) x{n} [{format_ts(first)}, {log}]")
        fan[(o, p)].add(r)
        add_finding(phase, "low", o, r, "lateral", f"{LATERAL_PORTS[p]} port {p} x{n}", format_ts(first), log)

    if len(internal) > DISPLAY_LIMIT:
        print(f"  ... {len(internal) - DISPLAY_LIMIT} more flow(s) in the export (--out, findings).")

    print(f"\n--- FAN-OUT: one source to >={FANOUT_MIN} internal targets on the same port ---")
    found = False
    for (o, p), dsts in sorted(fan.items(), key=lambda x: -len(x[1])):
        if len(dsts) >= FANOUT_MIN:
            found = True
            print(f"  [!] {o} -> {len(dsts)} targets over {LATERAL_PORTS[p]}/{p}: {', '.join(sorted(dsts)[:10])}"
                  f"{' ...' if len(dsts) > 10 else ''}")
            add_finding(phase, "high", o, "", "lateral_fanout", f"{len(dsts)} targets {LATERAL_PORTS[p]}/{p}")
    if not found:
        print("[-] No fan-out detected.")

    print(f"\n--- INBOUND ACCESS from the Internet to admin ports ({len(inbound)}) ---")
    for (o, r, p), (n, first, last, log) in sorted(inbound.items(), key=lambda x: x[1][1]):
        print(f"  [!] {o} ---> {r} (port {p}/{LATERAL_PORTS[p]}) x{n} [{format_ts(first)}, {log}]")
        add_finding(phase, "high", r, o, "admin_exposed", f"{LATERAL_PORTS[p]} port {p} x{n}", format_ts(first), log)

    print_pivots(phase, internal, inbound)


def print_pivots(phase, internal, inbound, top=None):
    """Pivot = internal host reached on an admin port (from an internal host or the Internet) that THEN opens
    admin connections to other internal hosts itself (A -> B -> C).
    Only outbound flows whose first connection follows the first entry count; connections back to the
    entry sources are ignored."""
    top = top or TOP_PIVOTS
    ins, outs = defaultdict(list), defaultdict(list)
    for src in (internal, inbound):
        for (o, r, p), (n, first, last, log) in src.items():
            ins[r].append((first, o, p))
    for (o, r, p), (n, first, last, log) in internal.items():
        outs[o].append((first, r, p, n))
    pivots = []
    for ip in set(ins) & set(outs):
        if not is_private_ip(ip):
            continue
        entries = sorted(ins[ip])
        t_in = entries[0][0]
        srcs = {s for _, s, _ in entries}
        hops = sorted(x for x in outs[ip] if x[0] >= t_in and x[1] not in srcs)
        if not hops:
            continue
        dsts = {d for _, d, _, _ in hops}
        from_net = sorted(s for s in srcs if not is_private_ip(s))
        pivots.append((ip, entries, hops, srcs, dsts, from_net))
    pivots.sort(key=lambda x: (not x[5], -len(x[4]), -len(x[3]), x[1][0][0]))

    print(f"\n--- TOP {min(top, len(pivots))} PIVOTS: internal hosts reached on an admin port that then "
          f"bounce to other internal hosts ({len(pivots)} in total; Internet first, then number of hops) ---")
    if not pivots:
        print("[-] No pivot detected.")
        return
    print(f"  {'Pivot IP':<15} {'Entries':>7} {'Hops':>7}  {'First entry':<20} {'First hop':<20} Entry ports -> hop ports")
    print("  " + "-" * 110)
    rows = []
    for ip, entries, hops, srcs, dsts, from_net in pivots:
        t_in, s_in, p_in = entries[0]
        t_out, d_out, p_out, _ = hops[0]
        p_ins = ",".join(sorted({LATERAL_PORTS[p] for _, _, p in entries}))
        p_outs = ",".join(sorted({LATERAL_PORTS[p] for _, _, p, _ in hops}))
        chain = (f"{s_in} →{LATERAL_PORTS[p_in]}→ {ip} →{LATERAL_PORTS[p_out]}→ {d_out}"
                 f"{f' (+{len(dsts) - 1} more target(s))' if len(dsts) > 1 else ''}")
        rows.append([ip, len(srcs), len(dsts), format_ts(t_in), format_ts(t_out), fmt_delay(t_out - t_in),
                     " ".join(sorted(srcs)), " ".join(sorted(dsts)), p_ins, p_outs, chain])
        sev = "high" if from_net or len(dsts) >= 2 else "medium"
        add_finding(phase, sev, ip, d_out, "lateral_pivot",
                    f"{chain} | entries={len(srcs)} hops={len(dsts)} first hop {fmt_delay(t_out - t_in)} "
                    f"after entry", format_ts(t_in))
    for ip, nsrc, ndst, t_in, t_out, delay, srcs, dsts, p_ins, p_outs, chain in rows[:top]:
        net = [s for s in srcs.split() if not is_private_ip(s)]
        print(f"  {'[!] ' if net else ''}{ip:<15} {nsrc:>7} {ndst:>7}  {t_in:<20} {t_out:<20} {p_ins} -> {p_outs}")
        print(f"      ↳ chain: {chain} | first hop {delay} after entry")
        print(f"      ↳ entries from: {cut(srcs, 70)}{' (Internet: ' + ', '.join(net) + ')' if net else ''}")
    if len(rows) > top:
        print(f"  ... {len(rows) - top} more pivot(s) in the export (--out).")
    print("[i] Domain controllers and file servers naturally have inbound and outbound admin flows: "
          "check the timing (entry -> hop delay) and the nature of the targets.")
    write_table("pivots", ["pivot_ip", "entries", "hops", "first_entry", "first_hop", "delay",
                           "entry_sources", "hop_targets", "entry_ports", "hop_ports", "chain"], rows)


def phase5_leak_hunting():
    phase = "5"
    reset_findings(phase)
    title("PHASE 5: Leak hunting / sensitive files (smb_files.log)")
    kws = load_keywords()
    if not kws:
        print("[!] No keyword loaded from keywords.txt.")
        return
    files = find_logs("smb_files")
    if not files:
        print("[-] No 'smb_files.log' file found.")
        return
    print(f"[+] {len(kws)} keyword(s); {len(files)} SMB log(s) (path/name/prev_name fields).")
    merged = {}
    for r in run_parallel(task_smb, files, {"kw": kws}):
        merged.update(r)
    print(f"\n--- RESULTS ({len(merged)} distinct files) ---")
    per_kw = Counter(k[4] for k in merged)
    if per_kw:
        print("  Breakdown: " + ", ".join(f"{k}={v}" for k, v in per_kw.most_common()))
    for i, ((o, r, action, text, kw, log), (n, ts, uid)) in enumerate(sorted(merged.items(), key=lambda x: x[1][1])):
        sev = "high" if kw in HIGH_VALUE_KEYWORDS else "medium"
        if i < DISPLAY_LIMIT:
            print(f"  [!] [{kw}] {format_ts(ts)} {o} -> {r} {action} x{n} uid={uid}\n      {text}\n      ({log})")
        add_finding(phase, sev, o, r, "smb_leak", f"{action} {text} [{kw}] x{n}", format_ts(ts), log, uid)
    if len(merged) > DISPLAY_LIMIT:
        print(f"  ... {len(merged) - DISPLAY_LIMIT} more lines in the export (--out).")


def phase6_dns():
    phase = "6"
    reset_findings(phase)
    title("PHASE 6: DNS anomalies (tunneling, DGA, NXDOMAIN, TXT)")
    files = find_logs("dns")
    if not files:
        print("[!] No dns.log found.")
        return
    subs, nx, ent, txt = defaultdict(set), Counter(), {}, Counter()
    for s, n, e, t in run_parallel(task_dns, files, build_ctx()):
        for k, v in s.items():
            subs[k] |= v
        nx.update(n)
        txt.update(t)
        for k, v in e.items():
            cur = ent.get(k)
            if cur is None:
                ent[k] = v
            else:
                cur[0] += v[0]
                cur[2] = max(cur[2], v[2])
                cur[3] = min(cur[3], v[3])

    print(f"\n--- POSSIBLE TUNNELING (>={DNS_TUNNEL_MIN_SUB} distinct subdomains under one domain) ---")
    f = False
    for (o, base), s in sorted(subs.items(), key=lambda x: -len(x[1])):
        if len(s) >= DNS_TUNNEL_MIN_SUB:
            f = True
            print(f"  [!] {o} -> *.{base} : {len(s)} subdomains (e.g. {next(iter(s))})")
            add_finding(phase, "high", o, base, "dns_tunnel", f"{len(s)} distinct subdomains")
    if not f:
        print("[-] Nothing to report.")

    print(f"\n--- HIGH-ENTROPY DOMAINS (possible DGA, >={DNS_DGA_MIN} queries) ---")
    f = False
    for (o, base), (n, ex, e, ts) in sorted(ent.items(), key=lambda x: -x[1][0]):
        if n >= DNS_DGA_MIN:
            f = True
            print(f"  [!] {o} -> {base} : {n} queries, max entropy {e:.2f} (e.g. {ex})")
            add_finding(phase, "medium", o, base, "dns_dga", f"{n} queries entropy={e:.2f} e.g.={ex}", format_ts(ts))
    if not f:
        print("[-] Nothing to report.")

    print(f"\n--- HIGH NXDOMAIN COUNT (>={DNS_NX_MIN} per host) ---")
    f = False
    for o, n in nx.most_common():
        if n >= DNS_NX_MIN:
            f = True
            print(f"  [!] {o} : {n} NXDOMAIN responses")
            add_finding(phase, "medium", o, "", "dns_nxdomain", f"{n} NXDOMAIN")
    if not f:
        print("[-] Nothing to report.")

    print(f"\n--- REPEATED TXT/NULL QUERIES (>={DNS_TXT_MIN}) ---")
    f = False
    for (o, base), n in txt.most_common():
        if n >= DNS_TXT_MIN:
            f = True
            print(f"  [!] {o} -> {base} : {n} TXT/NULL queries")
            add_finding(phase, "medium", o, base, "dns_txt", f"{n} TXT/NULL queries")
    if not f:
        print("[-] Nothing to report.")


def phase7_exfil_scan():
    phase = "7"
    reset_findings(phase)
    title("PHASE 7: Exfiltration (outbound volumes) & scans")
    data = get_conn_data()
    if not data:
        return
    flows, _, fails = data
    agg = {}
    for (o, r, p, proto, svc), (n, ob, rb, first, last, log) in flows.items():
        if classify_flow(o, r) != "out" or is_ip_whitelisted(r):
            continue
        a = agg.setdefault((o, r), [0, 0, 0, first, log])
        a[0] += n
        a[1] += ob
        a[2] += rb
        if first < a[3]:
            a[3], a[4] = first, log
    top = sorted(agg.items(), key=lambda x: -x[1][1])[:15]
    print("\n--- TOP 15 OUTBOUND VOLUMES (internal -> non-whitelisted public) ---")
    for (o, r), (n, ob, rb, first, log) in top:
        flag = ob >= EXFIL_MIN_BYTES or (ob >= 5 * 1024 * 1024 and ob > 10 * max(rb, 1))
        print(f"  {'[!]' if flag else '   '} {o} ---> {r} | sent {fmt_bytes(ob)} / received {fmt_bytes(rb)} "
              f"| {n} conn. [{format_ts(first)}, {log}]")
        if flag:
            add_finding(phase, "high", o, r, "exfil", f"sent {fmt_bytes(ob)} received {fmt_bytes(rb)}",
                        format_ts(first), log)

    print(f"\n--- SCANS (>={SCAN_MIN_TARGETS} failed (target, port) pairs: S0/REJ/RSTOS0/RSTRH) ---")
    f = False
    for o, s in sorted(fails.items(), key=lambda x: -len(x[1])):
        if len(s) < SCAN_MIN_TARGETS:
            continue
        f = True
        dsts, ports = {d for d, _ in s}, {p for _, p in s}
        if len(dsts) >= 20 and len(ports) <= 5:
            kind = "horizontal scan"
        elif len(ports) >= 50 and len(dsts) <= 3:
            kind = "vertical scan (ports)"
        else:
            kind = "mixed scan"
        print(f"  [!] {o} : {len(dsts)} targets / {len(ports)} ports -> {kind}")
        add_finding(phase, "high" if is_private_ip(o) else "info", o, "", "scan",
                    f"{kind}: {len(dsts)} targets, {len(ports)} ports")
    if not f:
        print("[-] No scan detected.")


# ======================================================================
# PHASE 8 : TLS (JA3/JA3S, certificats)
# ======================================================================
SSL_COLS = ["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "version", "server_name",
            "cert_chain_fuids", "validation_status", "ja3", "ja3s", "ja4", "subject", "issuer"]
X509_COLS = ["id", "fingerprint", "certificate.serial", "certificate.subject", "certificate.issuer",
             "certificate.not_valid_before", "certificate.not_valid_after", "certificate.key_alg",
             "certificate.key_length", "san.dns", "basic_constraints.ca"]
_X509_CACHE = None
_CN_RE = re.compile(r"CN=([^,/]+)")


def merge_counts(dst, src):
    """Merges {key: [n, ts, uid, log]} dicts, keeping the oldest ts."""
    for k, v in src.items():
        cur = dst.get(k)
        if cur is None:
            dst[k] = v
        else:
            cur[0] += v[0]
            if v[1] < cur[1]:
                cur[1:] = v[1:]


def task_ssl(path):
    out = {}
    for row in iter_zeek(path, SSL_COLS):
        o, r = row.get("id.orig_h"), row.get("id.resp_h")
        if not o or not r:
            continue

        def g(k):
            v = row.get(k, "-")
            return "" if v in UNSET else v

        chain = g("cert_chain_fuids")
        key = (o, r, g("id.resp_p"), g("server_name").lower(), g("ja3").lower(), g("ja3s").lower(),
               g("ja4"), g("version"), g("validation_status"),
               chain.split(",")[0] if chain else "", g("subject"), g("issuer"))
        ts = to_float(row.get("ts"))
        a = out.get(key)
        if a is None:
            out[key] = [1, ts, row.get("uid", ""), path]
        else:
            a[0] += 1
            if ts < a[1]:
                a[1], a[2] = ts, row.get("uid", "")
    return out


def task_x509(path):
    out = {}
    for row in iter_zeek(path, X509_COLS):
        fid = row.get("id")
        if not fid or fid in UNSET:
            continue
        out[fid] = (row.get("fingerprint", "").lower(), row.get("certificate.subject", "-"),
                    row.get("certificate.issuer", "-"), to_float(row.get("certificate.not_valid_before")),
                    to_float(row.get("certificate.not_valid_after")), row.get("certificate.key_alg", "-"),
                    row.get("certificate.key_length", "-"), row.get("san.dns", "-"),
                    row.get("certificate.serial", "-"))
    return out


def get_x509(force=False):
    global _X509_CACHE
    if _X509_CACHE is None or force:
        _X509_CACHE = {}
        files = find_logs("x509")
        if files:
            print(f"[*] Reading {len(files)} x509.log ...")
            for r in run_parallel(task_x509, files, {}):
                _X509_CACHE.update(r)
    return _X509_CACHE


def cert_names(subject, san):
    names = [n.strip().lower() for n in san.split(",") if n.strip() and n.strip() not in UNSET]
    m = _CN_RE.search(subject or "")
    if m:
        names.append(m.group(1).strip().lower())
    return names


def host_matches_cert(host, names):
    for n in names:
        if n == host or (n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]):
            return True
    return False


def phase8_tls():
    phase = "8"
    reset_findings(phase)
    title("PHASE 8: TLS: JA3/JA3S & certificates")
    files = find_logs("ssl")
    if not files:
        print("[!] No ssl.log found.")
        return
    ssl = {}
    for r in run_parallel(task_ssl, files, {}):
        merge_counts(ssl, r)
    x509 = get_x509()
    ioc_ja3, ioc_cert = load_ioc_database(IOC_JA3_FILE), load_ioc_database(IOC_CERTS_FILE)
    has_ja3 = any(k[4] or k[5] for k in ssl)
    print(f"[+] {len(ssl)} distinct TLS profiles | x509 certificates: {len(x509)} | "
          f"JA3 in logs: {'yes' if has_ja3 else 'no (zeek ja3 package missing?)'}")

    # --- A. IOC JA3 / JA3S ---
    print("\n--- JA3 / JA3S IOC ---")
    hits = 0
    for (o, r, port, sni, ja3, ja3s, ja4, ver, vs, fuid, subj, iss), (n, ts, uid, log) in \
            sorted(ssl.items(), key=lambda x: x[1][1]):
        for label, h in (("JA3", ja3), ("JA3S", ja3s)):
            if h and h in ioc_ja3:
                hits += 1
                print(f"  [!] {label} IOC [{ioc_ja3[h]}] {o} ---> {r}:{port} SNI={sni or '-'} x{n} "
                      f"hash={h} uid={uid} [{format_ts(ts)}, {log}]")
                add_finding(phase, "high", o, r, "ioc_" + label.lower(), f"{ioc_ja3[h]} {h} SNI={sni}",
                            format_ts(ts), log, uid)
    if not hits:
        print("[-] No JA3/JA3S IOC (feed ioc_ja3.txt through SSLBL ingestion).")

    # --- B. Certificats IOC ---
    print("\n--- IOC CERTIFICATES (x509 fingerprint) ---")
    hits = 0
    for (o, r, port, sni, ja3, ja3s, ja4, ver, vs, fuid, subj, iss), (n, ts, uid, log) in \
            sorted(ssl.items(), key=lambda x: x[1][1]):
        info = x509.get(fuid)
        if info and info[0] in ioc_cert:
            hits += 1
            print(f"  [!] CERT IOC [{ioc_cert[info[0]]}] {o} ---> {r}:{port} SNI={sni or '-'} "
                  f"fp={info[0]} subject={info[1]} uid={uid} [{format_ts(ts)}, {log}]")
            add_finding(phase, "high", o, r, "ioc_cert", f"{ioc_cert[info[0]]} {info[0]} {info[1]}",
                        format_ts(ts), log, uid)
    if not hits:
        print("[-] No IOC certificate (note: the x509 fingerprint length depends on the Zeek version).")

    # --- C. JA3 rares (inventaire) ---
    if has_ja3:
        by_ja3 = defaultdict(lambda: [set(), set(), 0])
        for (o, r, port, sni, ja3, *_), (n, ts, uid, log) in ssl.items():
            if ja3 and classify_flow(o, r) == "out":
                rec = by_ja3[ja3]
                rec[0].add(o)
                rec[1].add(sni or r)
                rec[2] += n
        rare = sorted(((j, rec) for j, rec in by_ja3.items() if len(rec[0]) <= JA3_RARE_MAX_HOSTS),
                      key=lambda x: -x[1][2])
        print(f"\n--- RARE JA3 (<={JA3_RARE_MAX_HOSTS} internal host): {len(rare)} (top 20) ---")
        for j, (hosts, snis, n) in rare[:20]:
            print(f"  [?] {j} | {', '.join(sorted(hosts))} | x{n} | SNI: {', '.join(sorted(snis)[:4])}")
        for j, (hosts, snis, n) in rare:
            add_finding(phase, "info", sorted(hosts)[0], "", "ja3_rare", f"{j} x{n} SNI={','.join(sorted(snis)[:3])}")

    # --- D. Certificate anomalies (outbound flows to public IPs) ---
    anomalies = {}
    for (o, r, port, sni, ja3, ja3s, ja4, ver, vs, fuid, subj, iss), (n, ts, uid, log) in ssl.items():
        if classify_flow(o, r) != "out" or is_ip_whitelisted(r):
            continue
        info = x509.get(fuid)
        if info:
            fp, subject, issuer, nvb, nva, kalg, klen, san, serial = info
        elif subj:
            fp, subject, issuer, nvb, nva, kalg, klen, san = "", subj, iss or "-", 0.0, 0.0, "-", "-", "-"
        else:
            continue  # no visible certificate (TLS 1.3, incomplete handshake...)
        flags, score = [], 0
        self_signed = subject not in UNSET and subject == issuer
        if self_signed:
            flags.append("self-signed")
            score += 2
        low = f"{subject} {issuer}".lower()
        mk = next((m for m in SUSPECT_CERT_MARKERS if m in low), None)
        if mk:
            flags.append(f"marker '{mk}'")
            score += 3
        if self_signed and not sni:
            flags.append("no SNI")
            score += 1
        if nva and nva < ts:
            flags.append("expired")
            score += 1
        if nvb and nvb > ts:
            flags.append("not yet valid")
            score += 1
        if nvb and nva:
            days = (nva - nvb) / 86400
            if days <= CERT_SHORT_DAYS:
                flags.append(f"short validity ({days:.1f} d)")
                score += 1
            elif days > CERT_LONG_DAYS:
                flags.append(f"very long validity ({days / 365:.0f} years)")
                score += 1
        if sni and not _IPV4_RE.fullmatch(sni):
            names = cert_names(subject, san)
            if names and not host_matches_cert(sni, names):
                flags.append("SNI≠CN/SAN")
                score += 1
        if kalg.lower() == "rsa" and klen.isdigit() and int(klen) < 2048:
            flags.append(f"RSA-{klen}")
            score += 1
        if score == 0:
            continue
        if vs and vs != "ok":
            flags.append(f"validation: {vs}")
        k = (o, r, port, sni, subject)
        cur = anomalies.get(k)
        if cur is None:
            anomalies[k] = [score, n, ts, uid, log, flags, issuer, ja3, fp]
        else:
            cur[1] += n
    print(f"\n--- CERTIFICATE ANOMALIES ({len(anomalies)} profiles, by decreasing score) ---")
    rows = sorted(anomalies.items(), key=lambda x: (-x[1][0], -x[1][1]))
    for i, ((o, r, port, sni, subject), (score, n, ts, uid, log, flags, issuer, ja3, fp)) in enumerate(rows):
        sev = "high" if score >= 4 else "medium" if score >= 2 else "low"
        if i < DISPLAY_LIMIT:
            print(f"  [{sev[0].upper()}:{score}] {o} ---> {r}:{port} SNI={sni or '-'} x{n} | {', '.join(flags)}\n"
                  f"        subject={subject} | issuer={issuer}"
                  f"{' | ja3=' + ja3 if ja3 else ''} | uid={uid} [{format_ts(ts)}, {log}]")
        add_finding(phase, sev, o, r, "cert_anomaly", f"{port} SNI={sni} {subject} :: {'; '.join(flags)}",
                    format_ts(ts), log, uid)
    if len(rows) > DISPLAY_LIMIT:
        print(f"  ... {len(rows) - DISPLAY_LIMIT} more profiles in the export (--out).")


# ======================================================================
# UID CORRELATION (menu c / --correlate) (conn <-> http/dns/ssl/files/smb/...)
# ======================================================================
SEED_COLS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
             "duration", "orig_bytes", "resp_bytes", "conn_state"]
TL_BASE = ["ts", "uid", "conn_uids", "id.orig_h", "id.resp_h"]
TL_SPECS = {
    "http": ["method", "host", "uri", "status_code", "user_agent", "resp_mime_types"],
    "dns": ["query", "qtype_name", "rcode_name", "answers"],
    "ssl": ["server_name", "version", "ja3", "ja3s", "validation_status", "cert_chain_fuids"],
    "files": ["fuid", "source", "mime_type", "filename", "total_bytes", "md5", "sha1", "sha256"],
    "smb_files": ["action", "path", "name", "prev_name", "size"],
    "smb_mapping": ["path", "service", "share_type"],
    "ntlm": ["username", "domainname", "hostname", "success", "status"],
    "kerberos": ["client", "service", "success", "error_msg"],
    "dce_rpc": ["endpoint", "operation"],
    "ssh": ["auth_success", "client", "server", "direction"],
    "ftp": ["user", "command", "arg"],
    "smtp": ["mailfrom", "rcptto", "from", "to", "subject", "fuids"],
    "smtp_received": ["trans_depth", "idx", "received"],
    "rdp": ["cookie", "result", "security_protocol"],
    "weird": ["name", "addl"],
    "notice": ["note", "msg"],
}
TL_SKIP_KINDS = {"conn", "x509", "stats", "capture_loss", "loaded_scripts", "reporter",
                 "packet_filter", "telemetry", "broker", "cluster", "known_hosts", "known_services",
                 "known_certs", "software", "dpd"}
TL_HIDE = {"cert_chain_fuids"}
MAX_SEED = 200000
MAX_EVENTS = 500000


def parse_time(s):
    """Accepts epoch, 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM[:SS]' (UTC)."""
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    print(f"[!] Date ignored (unknown format): {s}")
    return None


def task_seed(path):
    ip, uid, tmin, tmax = CTX["ip"], CTX["uid"], CTX["tmin"], CTX["tmax"]
    out = {}
    for row in iter_zeek(path, SEED_COLS):
        u = row.get("uid")
        if not u:
            continue
        if uid:
            if u != uid:
                continue
        elif CTX.get("uidset") is not None:
            if u not in CTX["uidset"]:
                continue
            if ip and row.get("id.orig_h") != ip and row.get("id.resp_h") != ip:
                continue
        elif row.get("id.orig_h") != ip and row.get("id.resp_h") != ip:
            continue
        ts = to_float(row.get("ts"))
        if ts < tmin or ts > tmax:
            continue
        out[u] = dict(row, ts=ts)
        if len(out) >= MAX_SEED:
            break
    return out


def task_timeline(item):
    kind, path = item
    uids, ips = CTX["uids"], CTX["ips"]
    spec = TL_SPECS.get(kind)
    cols = TL_BASE + spec if spec else None
    events, dnsmap = [], defaultdict(set)
    for row in iter_zeek(path, cols):
        if kind == "dns" and row.get("id.orig_h") in ips:
            ans, q = row.get("answers", "-"), row.get("query", "-")
            if ans not in UNSET and q not in UNSET:
                for a in ans.split(","):
                    if _IPV4_RE.fullmatch(a) or ":" in a:
                        dnsmap[a].add(q.lower())
        match = None
        u = row.get("uid")
        if u and u in uids:
            match = u
        else:
            cu = row.get("conn_uids", "-")
            if cu not in UNSET:
                for x in cu.split(","):
                    if x in uids:
                        match = x
                        break
        if match is None:
            continue
        fields = spec if spec else [k for k in row if k not in ("ts", "uid", "conn_uids", "id.orig_h", "id.resp_h")][:8]
        summ = " ".join(f"{k}={row[k]}" for k in fields if k not in TL_HIDE and row.get(k, "-") not in UNSET)
        chain = row.get("cert_chain_fuids", "-")
        fuid = chain.split(",")[0] if chain not in UNSET else ""
        events.append((to_float(row.get("ts")), match, kind, summ, path, fuid))
        if len(events) >= MAX_EVENTS:
            break
    return events, dict(dnsmap)


def correlate(target=None, since=None, until=None, limit=60, out_dir=None, only_events=False,
                     keyword=None):
    title("CORRELATION by uid (conn <-> http/dns/ssl/files/smb/ntlm/kerberos/smtp...)")
    if not target and not keyword:
        if not sys.stdin.isatty():
            print("[!] Target or keyword required: --correlate <IP|uid> and/or --keyword <word>")
            return
        target = input("IP or Zeek uid (empty = all sources): ").strip() or None
        keyword = input("Host/URI/SNI/DNS keyword, separated by | (e.g. example.com; empty = none): ").strip() or None
        since = since or input("Start (UTC, e.g. 2024-05-01 08:00; empty = none): ").strip() or None
        until = until or input("End   (UTC; empty = none): ").strip() or None
        only_events = input("Only sessions with application events? [y/N]: ").strip().lower() == "y"
    if not target and not keyword:
        return
    tmin = parse_time(since) if since else None
    tmax = parse_time(until) if until else None
    tmin = 0.0 if tmin is None else tmin
    tmax = float("inf") if tmax is None else tmax
    conn_files = find_logs("conn")
    if not conn_files:
        print("[!] No conn.log found.")
        return
    ip = uid = None
    if target:
        try:
            ipaddress.ip_address(target)
            ip = target
        except ValueError:
            uid = target
    if uid and keyword:
        print("[i] A specific uid was given: the keyword is ignored.")

    uidset = None
    if keyword and not uid:
        kws = [k.strip() for k in keyword.split("|") if k.strip()]
        items = [(k, p) for k in ("http", "ssl", "dns") for p in find_logs(k)]
        print(f"[*] Pass 0: searching {kws} in HTTP hosts/URIs, TLS SNI and DNS queries ...")
        uidset = set()
        for r in run_parallel(task_kw_uids, items, {"kw": kws}):
            uidset |= r
        if not uidset:
            print("[-] No occurrence of the keyword.")
            return
        print(f"[+] {len(uidset)} session(s) contain the keyword.")

    seeds = {}
    print(f"[*] Pass 1: sessions in conn.log (target={target or 'all'}, keyword={keyword or '-'}) ...")
    for r in run_parallel(task_seed, conn_files, {"ip": ip, "uid": uid, "uidset": uidset,
                                                  "tmin": tmin, "tmax": tmax}):
        seeds.update(r)
    if not seeds:
        print("[-] No session found for this target / time window.")
        return
    ips = {s.get("id.orig_h") for s in seeds.values()}

    items = [(k, p) for k, fl in get_index().items() if k not in TL_SKIP_KINDS for p in fl]
    print(f"[*] Pass 2: looking up {len(seeds)} uid(s) in {len(items)} log files ...")
    events, dnsmap = defaultdict(list), defaultdict(set)
    for ev, dm in run_parallel(task_timeline, items, {"uids": set(seeds), "ips": ips}):
        for e in ev:
            events[e[1]].append(e)
        for a, qs in dm.items():
            dnsmap[a] |= qs

    sessions = sorted(seeds.values(), key=lambda r: r["ts"])
    if only_events:
        sessions = [s for s in sessions if events.get(s["uid"])]
    kinds = Counter(e[2] for evs in events.values() for e in evs)
    svc = Counter(s.get("service", "-") for s in sessions)
    dst = Counter((s.get("id.orig_h") if (ip and s.get("id.resp_h") == ip) else s.get("id.resp_h"))
                  for s in sessions)
    print(f"\n[+] {len(sessions)} session(s) | services : {dict(svc.most_common(8))}")
    print(f"[+] Correlated events per log: {dict(kinds.most_common())}")
    print(f"[+] Most frequent peers: {', '.join(f'{k}({v})' for k, v in dst.most_common(8))}")
    x509 = get_x509() if kinds.get("ssl") else {}

    rows_out = []
    for i, s in enumerate(sessions):
        u = s["uid"]
        evs = sorted(events.get(u, []))
        o, r = s.get("id.orig_h", ""), s.get("id.resp_h", "")
        dom = f" DNS→{','.join(sorted(dnsmap[r])[:3])}" if r in dnsmap else ""
        head = (f"{o}:{s.get('id.orig_p', '-')} -> {r}:{s.get('id.resp_p', '-')}/{s.get('proto', '-')} "
                f"svc={s.get('service', '-')} dur={s.get('duration', '-')} "
                f"o/r={s.get('orig_bytes', '-')}/{s.get('resp_bytes', '-')} state={s.get('conn_state', '-')}{dom}")
        rows_out.append({"ts": format_ts(s["ts"]), "uid": u, "log": "conn", "info": head})
        show = i < limit
        if show:
            print(f"\n[{u}] {format_ts(s['ts'])} {head}")
        for ts, _, kind, summ, log, fuid in evs:
            rows_out.append({"ts": format_ts(ts), "uid": u, "log": kind, "info": summ})
            if show:
                print(f"      {format_ts(ts)} {kind:<11} {summ}")
            if kind == "ssl" and fuid in x509:
                fp, subject, issuer, nvb, nva, kalg, klen, san, serial = x509[fuid]
                line = (f"subject={subject} issuer={issuer} fp={fp} "
                        f"valid {format_ts(nvb)[:10]}→{format_ts(nva)[:10]} {kalg}-{klen}")
                rows_out.append({"ts": format_ts(ts), "uid": u, "log": "x509", "info": line})
                if show:
                    print(f"      {'':<20} └─ cert  {line}")
    if len(sessions) > limit:
        print(f"\n... {len(sessions) - limit} session(s) not shown (--limit, or export with --out).")
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target or keyword or "all")[:60]
        p = os.path.join(out_dir, f"timeline_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ts", "uid", "log", "info"])
            w.writeheader()
            w.writerows({k: csv_cell(v) for k, v in x.items()} for x in rows_out)
        print(f"[+] Timeline exported: {p} ({len(rows_out)} rows)")


# ======================================================================
# TLS IOC INGESTION (abuse.ch SSLBL: JA3 and certificates)
# ======================================================================
def ingest_tls_iocs(file_path):
    """Auto-detects: 32 hex = JA3 (MD5) -> ioc_ja3.txt; 40/64 hex = certificate fingerprint -> ioc_certs.txt."""
    hexre = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
    try:
        with _IOC_LOCK:
            ja3, certs = load_ioc_database(IOC_JA3_FILE), load_ioc_database(IOC_CERTS_FILE)
            n_j = n_c = 0
            with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
                for row in csv.reader(l for l in f if l.strip() and not l.startswith("#")):
                    for cell in row:
                        cell = cell.strip()
                        if not hexre.fullmatch(cell):
                            continue
                        label = row[-1].strip() if row[-1].strip() != cell else "malicious"
                        if len(cell) == 32 and cell.lower() not in ja3:
                            ja3[cell.lower()] = label
                            n_j += 1
                        elif len(cell) in (40, 64) and cell.lower() not in certs:
                            certs[cell.lower()] = label
                            n_c += 1
                        break
            _write_ioc_file(IOC_JA3_FILE, "# Format: ja3_md5|threat_type", ja3)
            _write_ioc_file(IOC_CERTS_FILE, "# Format: cert_fingerprint|threat_type", certs)
        print(f"[+] TLS ingestion: +{n_j} JA3, +{n_c} certificate fingerprints.")
    except Exception as e:
        print(f"[!] TLS ingestion failed: {e}")


# ======================================================================
# IOC INGESTION (Abuse.ch / URLhaus)
# ======================================================================
def _write_ioc_file(path, header, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        for k in sorted(data):
            f.write(f"{k}|{data[k]}\n")
    os.replace(tmp, path)


def ingest_abuse(file_path):
    """Ingests a URLhaus CSV/ZIP (column 3 = url, column 6 = threat), streamed, without extracting to disk."""
    zf = None
    try:
        if zipfile.is_zipfile(file_path):
            zf = zipfile.ZipFile(file_path)
            names = [n for n in zf.namelist() if n.lower().endswith((".csv", ".txt"))]
            if not names:
                print("[!] No CSV in the archive.")
                return
            text = io.TextIOWrapper(zf.open(names[0]), encoding="utf-8", errors="ignore", newline="")
        else:
            text = open(file_path, "r", encoding="utf-8", errors="ignore", newline="")
        added_ips = added_dom = 0
        with text, _IOC_LOCK:
            ip_iocs, dom_iocs = get_ioc_ips(), get_ioc_domains()
            for row in csv.reader(l for l in text if l.strip() and not l.startswith("#")):
                if len(row) < 6:
                    continue
                try:
                    host = urllib.parse.urlsplit(row[2]).hostname
                except ValueError:
                    continue
                if not host:
                    continue
                try:
                    ipaddress.ip_address(host)
                    if host not in ip_iocs:
                        ip_iocs[host] = row[5]
                        added_ips += 1
                except ValueError:
                    if host not in dom_iocs:
                        dom_iocs[host] = row[5]
                        added_dom += 1
            _write_ioc_file(IOC_IPS_FILE, "# Format: ip|threat_type", ip_iocs)
            _write_ioc_file(IOC_DOMAINS_FILE, "# Format: domain|threat_type", dom_iocs)
        print(f"\n[+] Ingestion done: +{added_ips} IPs, +{added_dom} domains.")
    except Exception as e:
        print(f"\n[!] Ingestion failed: {e}")
    finally:
        if zf:
            zf.close()


def manage_whitelists():
    global _NAMES_CACHE
    while True:
        print("\n" + "-" * 40 + "\n     WHITELISTS & IOC INGESTION\n" + "-" * 40)
        print("1. Show whitelists\n2. Add a legitimate domain or IP/CIDR")
        print("3. Ingest an Abuse.ch ZIP/CSV (background)\n4. Ingest an SSLBL CSV (JA3 / certificates)")
        print("5. Learn the IP whitelist (from whitelist.txt + dns/ssl/http)\n6. Import official ranges (AWS/Google/Microsoft/text)\n7. Back")
        try:
            choice = input("Choice (1-7): ").strip()
        except EOFError:
            break
        if choice == "1":
            for label, path in (("Domains", WHITELIST_FILE), ("IPs", IP_WHITELIST_FILE)):
                print(f"\n--- {label} ---")
                print("\n".join(_read_lines(path)))
        elif choice == "2":
            val = input("Domain, IP or CIDR to whitelist: ").strip().lower()
            if not val:
                continue
            try:
                ipaddress.ip_network(val, strict=False)
                target, is_ip = IP_WHITELIST_FILE, True
            except ValueError:
                target, is_ip = WHITELIST_FILE, False
            if val in _read_lines(target):
                print("[=] Already present.")
                continue
            with open(target, "a") as f:
                f.write(val + "\n")
            if is_ip:
                reload_ip_whitelist()
            print("[+] Added.")
        elif choice == "3":
            p = input("Path to the Abuse.ch ZIP/CSV: ").strip()
            if p and os.path.exists(p):
                threading.Thread(target=ingest_abuse, args=(p,)).start()
                print("[*] Ingestion started in the background.")
            else:
                print("[!] File not found.")
        elif choice == "4":
            p = input("Path to the SSLBL CSV (JA3 or certificates): ").strip()
            if p and os.path.exists(p):
                ingest_tls_iocs(p)
            else:
                print("[!] File not found.")
        elif choice == "5":
            learn_whitelist()
        elif choice == "6":
            p = input("Ranges file (JSON or text): ").strip()
            t = input("Service/tag filter (space-separated, empty = all): ").split()
            if p and os.path.exists(p):
                import_ranges(p, t)
            else:
                print("[!] File not found.")
        elif choice == "7":
            break


# ======================================================================
# IP WHITELIST: learning (DNS/SNI/HTTP), official range import, triage
# ======================================================================
LEARN_FILE = "ip_whitelist_learned.txt"
LEARN_MAP = "ip_whitelist_learned_map.csv"
CDN_RISKY_TAGS = {"CLOUDFRONT", "AMAZON", "CLOUDFRONT_ORIGIN_FACING", "AzureFrontDoor.Frontend"}


def task_names(item):
    """Public IP -> [sample of names (<=6), was at least one NON-whitelisted name seen on this IP?]."""
    kind, path = item
    wl = CTX.get("dom_wl", set())
    cols = {"dns": ["query", "answers"], "ssl": ["server_name", "id.resp_h"],
            "http": ["host", "id.resp_h"]}[kind]
    out, known = {}, {}
    for row in iter_zeek(path, cols):
        if kind == "dns":
            name, ips = row.get("query", "-"), row.get("answers", "-").split(",")
        else:
            name, ips = row.get(cols[0], "-"), [row.get("id.resp_h", "-")]
        if name in UNSET:
            continue
        name = strip_port(name.lower()).rstrip(".")
        ok = known.get(name)
        if ok is None:
            ok = known[name] = match_host(name, wl) is not None
        for ip in ips:
            if ip not in UNSET and ip_class(ip) == "public":
                rec = out.get(ip)
                if rec is None:
                    rec = out[ip] = [set(), False]
                if len(rec[0]) < 6:
                    rec[0].add(name)
                if not ok:
                    rec[1] = True
    return out


def collect_names(force=False):
    """(names per IP, IPs with at least one non-whitelisted name). Cached as long as whitelist.txt is unchanged."""
    global _NAMES_CACHE
    wl = load_domain_whitelist()
    key = frozenset(wl)
    if _NAMES_CACHE is None or force or _NAMES_CACHE[0] != key:
        items = [(k, p) for k in ("dns", "ssl", "http") for p in find_logs(k)]
        print("[*] Collecting names associated with public IPs (dns/ssl/http) ...")
        names, unknown = defaultdict(set), set()
        for r in run_parallel(task_names, items, {"dom_wl": wl}):
            for ip, (s, unk) in r.items():
                if len(names[ip]) < 6:
                    names[ip] |= s
                if unk:
                    unknown.add(ip)
        _NAMES_CACHE = (key, names, unknown)
    return _NAMES_CACHE[1], _NAMES_CACHE[2]


def learn_whitelist():
    """Whitelists the IPs whose observed names ALL belong to whitelist.txt (domains)."""
    title("IP WHITELIST LEARNING (from dns/ssl/http + whitelist.txt)")
    wl = load_domain_whitelist()
    if not wl:
        print("[!] whitelist.txt is empty.")
        return
    (names, unknown), ioc_ips = collect_names(), get_ioc_ips()
    learned, refused = {}, 0
    for ip, ns in names.items():
        if not ns or ip in ioc_ips:
            continue
        if ip in unknown:
            refused += 1
            continue
        learned[ip] = sorted(ns)[0]
    with open(LEARN_FILE, "w") as f:
        f.write("\n".join(sorted(learned, key=ipaddress.ip_address)) + ("\n" if learned else ""))
    with open(LEARN_MAP, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "domain"])
        w.writerows(sorted(learned.items()))
    reload_ip_whitelist()
    print(f"[+] {len(learned)} IPs learned -> {LEARN_FILE} (audit: {LEARN_MAP}). IOC IPs are excluded.")
    print(f"[i] {refused} IPs rejected because at least one non-whitelisted name was seen on them (shared IPs / CDN).")


def import_ranges(file_path, tags=None):
    """Imports official ranges: AWS ip-ranges.json, Google goog.json/cloud.json,
    Microsoft Service Tags .json, or text (1 CIDR per line, e.g. Cloudflare ips-v4)."""
    tags = set(tags or [])
    risky = tags & CDN_RISKY_TAGS
    if risky:
        print(f"[!] WARNING: {', '.join(sorted(risky))} covers CDNs/shared ranges that a C2 can use "
              "(e.g. *.cloudfront.net). These IPs will disappear from phases 0, 3, 7 and from triage.")
        if sys.stdin.isatty() and input("    Continue anyway? [y/N]: ").strip().lower() != "y":
            return
    found = set()
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    try:
        data = json.loads(raw)
        for p in data.get("prefixes", []) + data.get("ipv6_prefixes", []):
            if tags and p.get("service") not in tags:
                continue
            for k in ("ip_prefix", "ipv4Prefix", "ipv6_prefix", "ipv6Prefix"):
                if k in p:
                    found.add(p[k])
        for v in data.get("values", []):
            if tags and v.get("name") not in tags:
                continue
            found.update(v.get("properties", {}).get("addressPrefixes", []))
    except ValueError:
        found.update(l.strip() for l in raw.splitlines() if l.strip() and not l.startswith("#"))
    valid = set()
    for c in found:
        try:
            valid.add(str(ipaddress.ip_network(c, strict=False)))
        except ValueError:
            continue
    if not valid:
        print("[!] No valid range (for AWS/Microsoft JSON, check --tags).")
        return
    out = f"ip_whitelist_import_{re.sub(r'[^A-Za-z0-9_.-]', '_', os.path.splitext(os.path.basename(file_path))[0])}.txt"
    nets = sorted(valid, key=lambda c: (ipaddress.ip_network(c).version, ipaddress.ip_network(c)))
    with open(out, "w") as f:
        f.write("\n".join(nets) + "\n")
    reload_ip_whitelist()
    print(f"[+] {len(nets)} ranges imported -> {out}")


def phase_triage(top=40):
    title("TRIAGE: non-whitelisted public IPs, with or without an associated name")
    data = get_conn_data()
    if not data:
        return
    agg = {}
    for (o, r, p, proto, svc), (n, ob, rb, first, last, log) in data[0].items():
        kind = classify_flow(o, r)
        if kind not in ("out", "in"):
            continue
        pub = r if kind == "out" else o
        if is_ip_whitelisted(pub):
            continue
        tx, rx = (ob, rb) if kind == "out" else (rb, ob)
        a = agg.setdefault(pub, [0, 0, 0, set()])
        a[0] += n
        a[1] += tx
        a[2] += rx
        a[3].add(p)
    names, unknown = collect_names()
    ioc_ips = get_ioc_ips()
    nameless = sorted(((ip, a) for ip, a in agg.items() if ip not in names), key=lambda x: -x[1][1])
    named = sorted(((ip, a) for ip, a in agg.items() if ip in names), key=lambda x: -x[1][1])
    print(f"[+] {len(agg)} remaining public IPs: {len(named)} with a name (DNS/SNI/Host), "
          f"{len(nameless)} WITHOUT any associated name")
    print(f"\n--- NO ASSOCIATED NAME (direct connection to an IP: more suspicious), top {top} by bytes sent ---")
    for ip, (n, tx, rx, ports) in nameless[:top]:
        flag = "[IOC]" if ip in ioc_ips else "     "
        print(f"  {flag} {ip:<39} conn={n:<6} sent={fmt_bytes(tx):>9} received={fmt_bytes(rx):>9} "
              f"ports={','.join(sorted(ports)[:6])}")
    print(f"\n--- WITH A NAME (top {top} by bytes sent): candidates for whitelist.txt if legitimate ---")
    for ip, (n, tx, rx, ports) in named[:top]:
        flag = "[IOC]" if ip in ioc_ips else "     "
        print(f"  {flag} {ip:<39} conn={n:<6} sent={fmt_bytes(tx):>9} names={', '.join(sorted(names[ip])[:3])}")


# ======================================================================
# EMAILS (smtp.log): AGGREGATED TRIAGE
# ======================================================================
OUT_DIR = None
CLI_KEYWORD = None
CLI_MAIL_DIR = None
_ADDR_RE = re.compile(r"<([^>]+)>")
SMTP_COLS = ["ts", "uid", "id.orig_h", "id.resp_h", "helo", "mailfrom", "rcptto", "from", "to", "cc",
             "reply_to", "subject", "date", "x_originating_ip", "user_agent", "fuids", "tls", "is_webmail",
             "trans_depth", "path"]
MAX_LINKS_PER_MAIL = 500
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LINK_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}
_LINK_KW_RE = re.compile("|".join(re.escape(k) for k in LINK_KEYWORDS), re.I) if LINK_KEYWORDS else None


def max_sev(*levels):
    return max(levels, key=lambda s: _SEV_RANK.get(s, 0))


def write_table(name, header, rows):
    """Writes a CSV to OUT_DIR (when set via --out or menu 'e')."""
    if not OUT_DIR:
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    p = os.path.join(OUT_DIR, f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows([csv_cell(c) for c in row] for row in rows)
    print(f"[+] Table exported: {p} ({len(rows)} rows)")


def addr(v):
    if not v or v in UNSET:
        return ""
    m = _ADDR_RE.search(v)
    a = (m.group(1) if m else v.split(",")[0]).strip().strip('"')
    return "" if a in ("<>", "") else a  # MAIL FROM:<> = bounce, no sender


def addr_domain(a):
    return a.rsplit("@", 1)[1].lower() if "@" in a else ""


def addr_domains(*values):
    """Domains of all addresses in one or more fields (To, rcptto...)."""
    out = set()
    for v in values:
        if v:
            for _, a in email.utils.getaddresses([v]):
                d = addr_domain(a.strip("<>"))
                if d:
                    out.add(d)
    return out


def same_domain(a, b):
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def decode_mime(s):
    """Decodes '=?UTF-8?B?...?=' encoded subjects/names as logged by Zeek."""
    if not s or "=?" not in s:
        return s
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def short_rcpt(to):
    parts = [p for p in (to or "").split(",") if p.strip()]
    if not parts:
        return "-"
    first = addr(parts[0]) or parts[0].strip()
    return first + (f" +{len(parts) - 1}" if len(parts) > 1 else "")


def task_smtp(path):
    return [(to_float(r.get("ts")), r.get("uid", ""), r.get("id.orig_h", ""), r.get("id.resp_h", ""), r, path)
            for r in iter_zeek(path, SMTP_COLS)]


def task_smtp_files(path):
    out = {}
    for row in iter_zeek(path, ["fuid", "source", "mime_type", "filename", "total_bytes", "seen_bytes", "md5", "sha1",
                                "sha256"]):
        if row.get("source") == "SMTP" and row.get("fuid"):
            h = next((row.get(k) for k in ("sha256", "sha1", "md5") if row.get(k, "-") not in UNSET), "-")
            out[row["fuid"]] = (decode_mime(row.get("filename", "-")), row.get("mime_type", "-"),
                                # total_bytes is often unset for MIME parts: fall back to seen_bytes
                                row.get("total_bytes", "-") if row.get("total_bytes", "-") not in UNSET
                                else row.get("seen_bytes", "-"), h)
    return out


def new_mail_record(**kw):
    rec = {"ts": 0.0, "uid": "", "label": "OTHER", "kind": None, "o": "", "r": "", "mf": "", "from": "",
           "to": "", "cc": "", "subj": "", "rt": "", "atts": [], "bad_att": [], "fuids": [], "log": "",
           "flags": [], "score": 0, "links": {}, "sev": "info", "min_sev": "info", "date": "",
           "depth": "", "path": "", "helo": "", "orig_ip": "", "orig_name": "", "orig_src": "", "ua": ""}
    rec.update(kw)
    return rec


def build_mail_records(mails, attach, ext_re):
    labels = {"out": "SENT", "in": "RECEIVED", "int": "INTERNAL"}
    recs = []
    for ts, uid, o, r, row, log in mails:
        def g(k):
            v = row.get(k, "-")
            return "" if v in UNSET else v
        kind = classify_flow(o, r)
        fuids = [f for f in g("fuids").split(",") if f]
        # unnamed text/HTML parts are the message body, not attachments
        atts = [attach[f] for f in fuids if f in attach
                and not (attach[f][0] in UNSET and attach[f][1].startswith("text/"))]
        rec = new_mail_record(ts=ts, uid=uid, label=labels.get(kind, "OTHER"), kind=kind, o=o, r=r,
                              mf=addr(g("mailfrom")), to=g("to") or g("rcptto"), cc=g("cc"),
                              subj=decode_mime(g("subject")), rt=addr(g("reply_to")), atts=atts,
                              fuids=fuids, log=log, date=g("date"), depth=g("trans_depth"), path=g("path"),
                              helo=g("helo"), ua=g("user_agent"))
        rec["from"] = addr(decode_mime(g("from")))
        dm, df, dr = addr_domain(rec["mf"]), addr_domain(rec["from"]), addr_domain(rec["rt"])
        if dm and df and not same_domain(dm, df):
            rec["flags"].append(f"MAIL FROM ({dm}) ≠ From ({df})")
            rec["score"] += 2
        if dr and df and not same_domain(dr, df):
            rec["flags"].append(f"Reply-To ({dr}) ≠ From")
            rec["score"] += 2
        # Received from the Internet with a sender in the recipient's domain: internal domain spoofing
        if kind == "in":
            rcpt = addr_domains(g("to"), g("rcptto"))
            same = sorted({d for d in (df, dm) if d for rd in rcpt if same_domain(d, rd)})
            if same:
                rec["flags"].append(f"RECEIVED from the Internet with a sender in the recipient domain ({same[0]}): spoofing?")
                rec["score"] += 6
                rec["min_sev"] = "high"
        rec["bad_att"] = [a for a in atts if ext_re.search(a[0])]
        if rec["bad_att"]:
            rec["flags"].append("targeted attachment: " + ", ".join(cut(a[0], 40) for a in rec["bad_att"][:3]))
            rec["score"] += 4
        if rec["subj"] and SUBJECT_LURES.search(rec["subj"]):
            rec["flags"].append("lure subject")
            rec["score"] += 1
        recs.append(rec)
    return recs


# --- Real origin of an email (Received headers) ---
_RECV_FROM_RE = re.compile(r"\bfrom\s+(\S+)\s*(?:\(([^)]*)\))?", re.I)
_BRACKET_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")


def parse_received(text):
    """'from mail.x.us (unknown [1.2.3.4]) by ...' -> ('1.2.3.4', 'mail.x.us'). Name = reverse DNS recorded by the
    relay if any, else the HELO announced by the sender. None if the header has no 'from' clause."""
    m = _RECV_FROM_RE.search(text or "")
    if not m:
        return None
    helo, paren = m.group(1).strip("[]"), m.group(2) or ""
    ipm = _BRACKET_IP_RE.search(paren) or _BRACKET_IP_RE.search(m.group(1))
    ip = ipm.group(1) if ipm else (helo if _IPV4_RE.fullmatch(helo) else "")
    before = paren.split("[")[0].split()
    rdns = before[0] if before else ""
    name = rdns if rdns and rdns.lower() != "unknown" and not _IPV4_RE.fullmatch(rdns) else helo
    return ip, ("" if name == ip else name)


def task_smtp_received(path):
    """smtp_received.log (Zeek script): (uid, trans_depth) -> [(order, Received header text)]."""
    out = defaultdict(list)
    for row in iter_zeek(path, ["uid", "trans_depth", "idx", "received"]):
        idx = row.get("idx", "0")
        out[(row.get("uid", ""), row.get("trans_depth", ""))].append(
            (int(idx) if idx.isdigit() else 0, row.get("received", "")))
    return dict(out)


def task_dns_names(path):
    """DNS names (A/AAAA answers) of origin IPs that have no name."""
    ips, out = CTX["ips"], {}
    for row in iter_zeek(path, ["query", "answers"]):
        q, ans = row.get("query", "-"), row.get("answers", "-")
        if q in UNSET or ans in UNSET:
            continue
        for a in ans.split(","):
            if a in ips and a not in out:
                out[a] = q.lower().rstrip(".")
    return out


def resolve_origins(recs):
    """Origin of a RECEIVED email: the first public IP in the Received headers read top-down, i.e. the one
    recorded by the first trusted relay (lower headers are written by the sender and can be forged).
    Source: smtp_received.log (Zeek script); otherwise the 'path' field of smtp.log (IPs only)."""
    recv = {}
    for r in run_parallel(task_smtp_received, find_logs("smtp_received"), {}):
        for k, v in r.items():
            recv.setdefault(k, []).extend(v)
    n = 0
    for rec in recs:
        if not rec["uid"]:
            continue
        hdrs = sorted(recv.get((rec["uid"], rec["depth"]), []))
        for _, text in hdrs:
            p = parse_received(text)
            if p and p[0] and ip_class(p[0]) == "public" and p[0] != rec["o"]:
                rec["orig_ip"], rec["orig_name"], rec["orig_src"] = p[0], p[1], "Received"
                break
        if not rec["orig_ip"] and rec["path"]:
            # Zeek path = [server, seen client, Received IPs...]: skip the first 2
            for ip in rec["path"].split(",")[2:]:
                ip = ip.strip()
                if ip_class(ip) == "public" and ip != rec["o"]:
                    rec["orig_ip"], rec["orig_src"] = ip, "path"
                    break
        if rec["orig_ip"]:
            n += 1
    missing = {r["orig_ip"] for r in recs if r["orig_ip"] and not r["orig_name"]}
    if missing:
        names = {}
        for r in run_parallel(task_dns_names, find_logs("dns"), {"ips": missing}):
            for ip, q in r.items():
                names.setdefault(ip, q)
        for rec in recs:
            if rec["orig_ip"] and not rec["orig_name"]:
                rec["orig_name"] = names.get(rec["orig_ip"], "")
    if not recv:
        print("[i] smtp_received.log missing: origin taken from the 'path' field (IPs only, name via dns.log when "
              "possible). Re-run Zeek with the updated script to get relay names.")
    return n


# --- Sending client (User-Agent / X-Mailer from smtp.log) ---
_MAILER_TOOLS_RE = re.compile(
    r"\b(phpmailer|gophish|king ?phisher|swaks|sendemail|sendblaster|atomic ?mail|turbo-?mailer|mass ?mailer|"
    r"bulk ?mail|python|powershell|perl|curl|wget|java|go-http|microsoft cdo|ruby|nodemailer|emkei)\b", re.I)
_UA_FAMILIES = (
    ("outlook", "Outlook"), ("microsoft office", "Outlook"), ("exchange", "Exchange"),
    ("thunderbird", "Thunderbird"), ("apple mail", "Apple Mail"), ("iphone mail", "Apple Mail (iOS)"),
    ("ipad mail", "Apple Mail (iOS)"), ("android", "Android"), ("gmail", "Gmail"), ("roundcube", "Roundcube"),
    ("zimbra", "Zimbra"), ("lotus", "Lotus Notes"), ("evolution", "Evolution"), ("kmail", "KMail"),
    ("mutt", "Mutt"), ("postbox", "Postbox"), ("em client", "eM Client"), ("mailbird", "Mailbird"),
)


def ua_family(ua):
    """Sending client family, without version: 'Mozilla/5.0 (...) Thunderbird/102.6.1' -> 'Thunderbird'."""
    low = ua.lower()
    for key, fam in _UA_FAMILIES:
        if key in low:
            return fam
    m = _MAILER_TOOLS_RE.search(ua)
    if m:
        return m.group(1).strip().title()
    first = re.split(r"[/\s(;]", ua.strip(), 1)[0]
    return first or "?"


def check_user_agents(recs):
    """Suspicious mailing tool, and unusual client for the sender domain (baseline = all emails from
    that domain in the capture). Returns (suspicious tool count, unusual client count)."""
    base = defaultdict(Counter)
    for rec in recs:
        dom = addr_domain(rec["from"] or rec["mf"])
        if dom:
            base[dom][ua_family(rec["ua"]) if rec["ua"] else "(none)"] += 1
    n_tool = n_rare = 0
    for rec in recs:
        if not rec["ua"]:
            continue
        m = _MAILER_TOOLS_RE.search(rec["ua"])
        if m:
            rec["flags"].append(f"suspicious mailing tool ({m.group(1)}): {cut(rec['ua'], 60)}")
            rec["score"] += 3
            rec["min_sev"] = max_sev(rec["min_sev"], "medium")
            n_tool += 1
        dom = addr_domain(rec["from"] or rec["mf"])
        c = base.get(dom)
        if not c:
            continue
        total, fam = sum(c.values()), ua_family(rec["ua"])
        if total >= UA_BASELINE_MIN and c[fam] / total <= UA_RARE_RATIO:
            usual, nu = c.most_common(1)[0]
            rec["flags"].append(f"unusual client for {dom}: {fam} ({c[fam]}/{total} emails), "
                                f"usual: {usual} ({nu}/{total})")
            rec["score"] += 3
            rec["min_sev"] = max_sev(rec["min_sev"], "medium")
            n_rare += 1
    return n_tool, n_rare


def fmt_origin(rec):
    if not rec["orig_ip"]:
        return ""
    return f"{rec['orig_ip']} ({rec['orig_name'] or 'unknown name'})"


# --- Links in bodies (smtp-<fuid> files extracted by Zeek, or .eml) ---
_URL_RE = re.compile(r"""https?://[^\s<>"'\)\]]{1,2000}""", re.I)
_HREF_RE = re.compile(r"""<a\s[^>]{0,500}?href\s*=\s*["']?([^"'\s>]{1,2000})["']?[^>]{0,500}>(.{0,300}?)</a>""",
                      re.I | re.S)
_FUID_RE = re.compile(r"F[A-Za-z0-9]{10,20}")
_BARE_DOMAIN_RE = re.compile(r"(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.I)
_BODY_EXTS = (".eml", ".html", ".htm", ".txt")


def links_from_text(text):
    """[(url, displayed_text)] from HTML (href) or plain text."""
    links, seen = [], set()
    for m in _HREF_RE.finditer(text):
        url = html.unescape(m.group(1)).strip()
        label = html.unescape(re.sub(r"<[^>]{0,200}>", "", m.group(2))).strip()
        if len(links) >= MAX_LINKS_PER_MAIL:
            break
        if url.lower().startswith(("http://", "https://")) and url not in seen:
            seen.add(url)
            links.append((url, label))
    for u in _URL_RE.findall(text):
        u = html.unescape(u).rstrip(".,;")
        if len(links) >= MAX_LINKS_PER_MAIL:
            break
        if u not in seen:
            seen.add(u)
            links.append((u, ""))
    return links


def link_host(url):
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def analyze_link(url, label, ioc_hosts, wl=None):
    try:
        return _analyze_link(url, label, ioc_hosts, wl or set())
    except Exception:
        return "info", ["unparsable link"]


def _analyze_link(url, label, ioc_hosts, wl):
    host = link_host(url)
    if not host:
        return "info", []
    flags, sev = [], "info"

    def bump(level):
        nonlocal sev
        if _SEV_RANK[level] > _SEV_RANK[sev]:
            sev = level

    hit = match_host(host, ioc_hosts)
    if hit:
        flags.append(f"IOC [{ioc_hosts[hit]}]")
        bump("high")
    m = _LINK_KW_RE.search(f"{url} {label}") if _LINK_KW_RE else None
    if m:
        kw = m.group(0).lower()
        if hit or not match_host(host, wl):  # an IOC overrides the whitelist
            flags.append(f"keyword '{kw}'")
            bump("critical")
        else:
            flags.append(f"keyword '{kw}' (whitelisted domain)")
            bump("low")
    if host in SHORTENERS:
        flags.append("URL shortener")
        bump("low")
    if _IPV4_RE.fullmatch(host):
        flags.append("literal IP")
        bump("medium")
    if "xn--" in host:
        flags.append("punycode")
        bump("medium")
    if label:
        shown = None
        if label.lower().startswith(("http://", "https://")):
            shown = link_host(label) or None
        elif _BARE_DOMAIN_RE.fullmatch(label.strip()):
            shown = label.strip().lower()
        if shown and not same_domain(shown.replace("www.", "", 1), host.replace("www.", "", 1)):
            flags.append(f"displayed text ({shown}) != destination")
            bump("medium")
    return sev, flags


def is_body_candidate(name):
    """Body extracted by Zeek (smtp-<fuid>, with or without extension) or a .eml/.html/.htm/.txt file."""
    low = name.lower()
    return low.startswith("smtp-") or low.endswith(_BODY_EXTS)


def scan_mail_dir(mail_dir, attach):
    out, n = [], 0
    for root, _, files in os.walk(mail_dir):
        # Only Zeek extract_files folders, or folders containing bodies/.eml, are read
        if "extract_files" not in root.split(os.sep) and not any(is_body_candidate(f) for f in files):
            continue
        for name in files:
            if not is_body_candidate(name):
                continue
            n += 1
            if n % 2000 == 0:
                sys.stderr.write(f"\r    {n} files checked, {len(out)} with links")
                sys.stderr.flush()
            p = os.path.join(root, name)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if size == 0 or size > 5 * 1024 * 1024:
                continue
            low, fuid, meta = name.lower(), "", None
            try:
                if low.endswith(".eml"):
                    with open(p, "rb") as f:
                        msg = email.message_from_binary_file(f, policy=email.policy.default)
                    text = ""
                    for part in msg.walk():
                        if part.get_content_maintype() == "text":
                            try:
                                text += part.get_content() + "\n"
                            except Exception:
                                continue
                    meta = {k: str(msg.get(k, "")) for k in ("From", "To", "Subject", "Date")}
                else:
                    m = _FUID_RE.search(name)
                    fuid = m.group(0) if m else ""
                    info = attach.get(fuid)
                    # known fuid: trust the files.log mime_type; otherwise the name is enough
                    # (the Zeek script only extracts text/html and text/plain parts)
                    if info and not info[1].startswith("text/"):
                        continue
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
            except Exception as e:  # an unreadable file must not stop the analysis
                sys.stderr.write(f"\n[!] {p} skipped: {e}\n")
                continue
            links = links_from_text(text)
            if links:
                out.append((p, fuid, meta, links))
    if n >= 2000:
        sys.stderr.write("\n")
    return out


def resolve_mail_dir():
    """--mail-dir, else ./zeek_output if it exists, else the log root (Zeek extracts the bodies there)."""
    if CLI_MAIL_DIR is not None:
        return CLI_MAIL_DIR
    default = DEFAULT_MAIL_DIR if os.path.isdir(DEFAULT_MAIL_DIR) else LOG_ROOT
    if sys.stdin.isatty():
        raw = input(f"Folder of extracted email bodies / .eml [default: {default}] (- = skip): ").strip()
        return None if raw == "-" else (raw or default)
    return default


def attach_links(recs, attach):
    """Attaches links from extracted bodies to smtp.log emails (by fuid, else by subject+sender)."""
    mail_dir = resolve_mail_dir()
    if not mail_dir or not os.path.isdir(mail_dir):
        n_text = sum(1 for a in attach.values() if a[1].startswith("text/"))
        if mail_dir:
            print(f"[!] Folder not found: {mail_dir}")
        print(f"[i] Links not analyzed: smtp.log does not contain the bodies ({n_text} text/HTML part(s) "
              "listed in files.log). Use --mail-dir <folder> ('smtp-<fuid>' files extracted by Zeek, "
              "or .eml files from tshark --export-objects imf,<folder>).")
        return 0, 0
    print(f"[*] Reading email bodies in {mail_dir} ...")
    by_fuid = {f: rec for rec in recs for f in rec["fuids"]}
    by_meta = defaultdict(list)
    for rec in recs:
        by_meta[((rec["subj"] or "").strip().lower(), rec["from"].lower())].append(rec)
    ioc_hosts = {**get_ioc_ips(), **get_ioc_domains()}
    wl = load_domain_whitelist()
    results = scan_mail_dir(mail_dir, attach)
    n_links = 0
    for path, fuid, meta, links in results:
        rec = by_fuid.get(fuid)
        if rec is None and meta:
            cands = by_meta.get((meta["Subject"].strip().lower(), addr(meta["From"]).lower()), [])
            rec = cands[0] if len(cands) == 1 else None
        if rec is None:
            ts = 0.0
            if meta and meta.get("Date"):
                try:
                    ts = email.utils.parsedate_to_datetime(meta["Date"]).timestamp()
                except (TypeError, ValueError, IndexError):
                    ts = 0.0
            rec = new_mail_record(ts=ts, label=".EML" if meta else "ORPHAN", log=path,
                                  **({"from": addr(meta["From"]), "to": meta["To"], "subj": meta["Subject"],
                                      "date": meta["Date"]}
                                     if meta else {}))
            recs.append(rec)
        for u, l in links:
            if len(rec["links"]) >= MAX_LINKS_PER_MAIL:
                break
            n_links += 1
            sev, flags = analyze_link(u, l, ioc_hosts, wl)
            cur = rec["links"].get(u)
            if cur and _SEV_RANK[cur["sev"]] >= _SEV_RANK[sev]:
                continue  # same link in text and HTML versions: keep the most severe
            host = link_host(u)
            rec["links"][u] = {"url": u, "label": l, "sev": sev, "flags": flags, "host": host,
                               "wl": bool(host and match_host(host, wl)), "file": path, "visit": None}
    return len(results), n_links


def task_seen_hosts(item):
    """First visits (ts, ip, log) of link hosts, in http (Host), ssl (SNI) and dns (query)."""
    kind, path = item
    hosts, col = CTX["hosts"], DOMAIN_FIELD[kind]
    out = defaultdict(list)
    for row in iter_zeek(path, ["ts", "id.orig_h", col]):
        v = row.get(col, "-")
        if v in UNSET:
            continue
        h = strip_port(v.lower()).rstrip(".")
        if h in hosts:
            lst = out[h]
            if len(lst) < 500:
                lst.append((to_float(row.get("ts")), row.get("id.orig_h", ""), kind))
    return dict(out)


def mark_visits(recs):
    hosts = {l["host"] for rec in recs for l in rec["links"].values() if l["host"] and not l["wl"]}
    if not hosts:
        return
    items = [(k, p) for k in ("http", "ssl", "dns") for p in find_logs(k)]
    print(f"[*] Looking for visits to {len(hosts)} link domain(s) in http/ssl/dns ...")
    seen = defaultdict(list)
    for r in run_parallel(task_seen_hosts, items, {"hosts": hosts}):
        for h, lst in r.items():
            seen[h].extend(lst)
    for lst in seen.values():
        lst.sort()
    for rec in recs:
        for l in rec["links"].values():
            lst = seen.get(l["host"])
            if not lst:
                continue
            if not rec["ts"]:
                l["visit"] = lst[0]
                continue
            i = bisect.bisect_left(lst, (rec["ts"] - 60,))
            if i < len(lst) and lst[i][0] - rec["ts"] <= CLICK_WINDOW:
                l["visit"] = lst[i]


def score_mails(recs):
    for rec in recs:
        links = list(rec["links"].values())
        flagged = [l for l in links if l["flags"]]
        visited = [l for l in links if l["visit"]]
        if flagged:
            rec["score"] += min(10, sum(LINK_WEIGHT[l["sev"]] for l in flagged))
        if visited:
            rec["score"] += 4 if any(l["flags"] for l in visited) else 2
        rec["n_flagged"], rec["n_visited"] = len(flagged), len(visited)
        worst = max((l["sev"] for l in links), key=_SEV_RANK.get, default="info")
        s = rec["score"]
        sev = ("critical" if worst == "critical" else "high" if s >= 8 or worst == "high" else
               "medium" if s >= 4 else "low" if s >= 2 else "info")
        rec["sev"] = max_sev(sev, rec["min_sev"])


def worst_link(rec):
    links = list(rec["links"].values())
    if not links:
        return None
    return max(links, key=lambda l: (_SEV_RANK[l["sev"]], l["visit"] is not None, not l["wl"]))


def mail_reasons(rec):
    out = list(rec["flags"])
    agg = Counter()
    for l in rec["links"].values():
        for f in l["flags"]:
            agg["displayed text != destination" if f.startswith("displayed text") else f] += 1
    out += [f"link {f} x{n}" if n > 1 else f"link {f}" for f, n in agg.most_common(4)]
    visited = [l for l in rec["links"].values() if l["visit"]]
    if visited:
        l = min(visited, key=lambda x: x["visit"][0])
        ts, ip, kind = l["visit"]
        delay = f" {fmt_delay(ts - rec['ts'])}" if rec["ts"] else ""
        more = f" (+{len(visited) - 1} more)" if len(visited) > 1 else ""
        out.append(f"VISITED: {l['host']} by {ip} via {kind}{delay}{more}")
    return out


def print_top_mails(recs, top):
    sus = sorted((r for r in recs if r["score"] > 0), key=lambda r: (-_SEV_RANK[r["sev"]], -r["score"], r["ts"]))
    print(f"\n--- TOP {min(top, len(sus))} SUSPICIOUS EMAILS (out of {len(sus)} with at least one signal, "
          f"by decreasing severity then score) ---")
    if not sus:
        print("[-] No email shows any signal.")
        return
    print("     (!!! critical, !! high, ! medium, ? low)")
    print(f" {'Sc':>4} {'Date (UTC)':<20} {'Dir.':<8} {'From':<30} {'To':<26} {'Links':>6} {'Att':>3}  Subject")
    print(" " + "-" * 129)
    for rec in sus[:top]:
        date = format_ts(rec["ts"]) if rec["ts"] else "-"
        links = f"{rec['n_flagged']}/{len(rec['links'])}" if rec["links"] else "-"
        pj = f"{len(rec['bad_att'])}!" if rec["bad_att"] else (str(len(rec["atts"])) if rec["atts"] else "-")
        sender = rec["from"] or rec["mf"] or "-"
        mark = {"critical": "!!!", "high": "!!", "medium": "!", "low": "?"}.get(rec["sev"], "")
        print(f"{mark:<3}{rec['score']:>3} {date:<20} {rec['label']:<8} {cut(sender, 30):<30} "
              f"{cut(short_rcpt(rec['to']), 26):<26} {links:>6} {pj:>3}  {cut(rec['subj'] or '-', 45)}")
        helo = f" ({rec['helo']})" if rec["helo"] else ""
        ips = f"{rec['o']}{helo} -> {rec['r']} uid={rec['uid']}" if rec["uid"] else rec["log"]
        print(f"      ↳ {ips}")
        extra = []
        if rec["orig_ip"]:
            extra.append(f"origin ({rec['orig_src']}): {fmt_origin(rec)}")
        if rec["date"]:
            extra.append(f"Date (header): {fmt_mail_date(rec['date'])}")
        if extra:
            print(f"      ↳ {' | '.join(extra)}")
        print(f"      ↳ {'; '.join(mail_reasons(rec))}")
        wl = worst_link(rec)
        if wl and (wl["flags"] or wl["visit"]):
            print(f"      ↳ link: {defang(cut(wl['url'], 110))}")
    if len(sus) > top:
        print(f"  ... {len(sus) - top} more email(s) with signals in the export (--out).")


def print_link_domains(recs, top):
    dom, hidden = {}, 0
    for rec in recs:
        for l in rec["links"].values():
            h = l["host"]
            if not h:
                continue
            if l["wl"]:
                hidden += 1
                continue
            d = dom.get(h)
            if d is None:
                d = dom[h] = {"mails": set(), "n": 0, "rcpt": set(), "first": 0.0, "sev": "info",
                              "flags": Counter(), "visits": set()}
            d["mails"].add(id(rec))
            d["n"] += 1
            d["rcpt"].add(short_rcpt(rec["to"]).split(" +")[0])
            if rec["ts"] and (not d["first"] or rec["ts"] < d["first"]):
                d["first"] = rec["ts"]
            if _SEV_RANK[l["sev"]] > _SEV_RANK[d["sev"]]:
                d["sev"] = l["sev"]
            for f in l["flags"]:
                d["flags"]["text!=dest" if f.startswith("displayed text") else f] += 1
            if l["visit"]:
                d["visits"].add(l["visit"][1])
    print(f"\n--- TOP {min(top, len(dom))} LINK DOMAINS ({len(dom)} non-whitelisted domains, "
          f"{hidden} whitelisted link(s) hidden) ---")
    if not dom:
        print("[-] No link extracted.")
        return []
    print(f" {'Sev':<4} {'Domain':<42} {'Mails':>5} {'Links':>5} {'Rcpt.':>5}  {'First seen':<20} {'Visited by':<22} Signals")
    print(" " + "-" * 128)
    rows = sorted(dom.items(), key=lambda x: (-_SEV_RANK[x[1]["sev"]], -len(x[1]["visits"]), -len(x[1]["mails"])))
    for h, d in rows[:top]:
        sev = {"critical": "!!!", "high": "!!", "medium": "!", "low": "?"}.get(d["sev"], "")
        vis = ", ".join(sorted(d["visits"])[:2]) + (" ..." if len(d["visits"]) > 2 else "") if d["visits"] else "-"
        sig = ", ".join(f"{f}" for f, _ in d["flags"].most_common(2)) or "-"
        first = format_ts(d["first"]) if d["first"] else "-"
        print(f" {sev:<4} {cut(h, 42):<42} {len(d['mails']):>5} {d['n']:>5} {len(d['rcpt']):>5}  "
              f"{first:<20} {cut(vis, 22):<22} {cut(sig, 40)}")
    return rows


def print_senders(recs, top):
    snd = {}
    for rec in recs:
        if rec["label"] == "SENT":
            continue
        dom = addr_domain(rec["from"] or rec["mf"]) or "(unknown)"
        s = snd.get(dom)
        if s is None:
            s = snd[dom] = [0, 0, set(), 0.0, 0]
        s[0] += 1
        if rec["score"] >= 2:
            s[1] += 1
        s[2].add(short_rcpt(rec["to"]).split(" +")[0])
        if rec["ts"] and (not s[3] or rec["ts"] < s[3]):
            s[3] = rec["ts"]
        s[4] = max(s[4], rec["score"])
    rows = sorted((x for x in snd.items() if x[1][1]), key=lambda x: (-x[1][4], -x[1][1]))
    print(f"\n--- SENDER DOMAINS WITH SIGNALS (top {min(top, len(rows))} of {len(rows)}) ---")
    if not rows:
        print("[-] None.")
        return
    print(f" {'Domain (From)':<40} {'Mails':>5} {'Suspic.':>8} {'Rcpt.':>5} {'Max score':>9}  First seen")
    for dom, (n, sus, rcpt, first, mx) in rows[:top]:
        print(f" {cut(dom, 40):<40} {n:>5} {sus:>8} {len(rcpt):>5} {mx:>9}  {format_ts(first) if first else '-'}")


def print_mail_details(recs):
    sus = sorted((r for r in recs if r["score"] > 0), key=lambda r: r["ts"])
    print(f"\n--- DETAILS OF THE {min(len(sus), DISPLAY_LIMIT)} EMAILS WITH SIGNALS (chronological order) ---")
    for rec in sus[:DISPLAY_LIMIT]:
        print(f"\n  [{rec['label']}] {format_ts(rec['ts']) if rec['ts'] else '-'} {rec['o']} -> {rec['r']} "
              f"uid={rec['uid'] or '-'} score={rec['score']}")
        print(f"      From: {rec['from'] or '-'} (MAIL FROM: {rec['mf'] or '-'}) | To: {cut(rec['to'], 120) or '-'}"
              f"{' | Cc: ' + cut(rec['cc'], 60) if rec['cc'] else ''}")
        print(f"      Subject: {cut(rec['subj'], 150) or '-'}")
        if rec["date"]:
            print(f"      Date (header, sender's time zone): {fmt_mail_date(rec['date'])}")
        if rec["ua"]:
            print(f"      Sending client: {cut(rec['ua'], 140)}")
        if rec["helo"] or rec["orig_ip"]:
            print(f"      Relay seen (HELO): {rec['helo'] or '-'} | origin ({rec['orig_src'] or '-'}): "
                  f"{fmt_origin(rec) or '-'}")
        for a in rec["atts"]:
            print(f"      Attachment: {a[0]} ({a[1]}, {a[2]} bytes) hash={a[3]}{' [!]' if a in rec['bad_att'] else ''}")
        links = sorted(rec["links"].values(), key=lambda l: (-_SEV_RANK[l["sev"]], l["visit"] is None))
        for l in links[:15]:
            extra = list(l["flags"])
            if l["visit"]:
                extra.append(f"visited by {l['visit'][1]} ({l['visit'][2]}) {format_ts(l['visit'][0])}")
            print(f"      {'[!]' if extra else '   '} {defang(cut(l['url'], 140))}"
                  f"{'  <- ' + '; '.join(extra) if extra else ''}")
        if len(links) > 15:
            print(f"      ... {len(links) - 15} more link(s)")


def email_triage(exts):
    title("EMAILS: triage of suspicious messages (smtp.log + files.log + extracted bodies)")
    files = find_logs("smtp")
    mails = []
    if files:
        for r in run_parallel(task_smtp, files, {}):
            mails.extend(r)
    else:
        print("[-] No smtp.log found (.eml files from --mail-dir are still analyzed).")
    mails.sort(key=lambda m: m[0])
    attach = {}
    for r in run_parallel(task_smtp_files, find_logs("files"), {}):
        attach.update(r)
    ext_re = re.compile("(?:" + "|".join(re.escape(e) for e in exts) + r")\s*$", re.I)

    recs = build_mail_records(mails, attach, ext_re)
    resolve_origins(recs)
    n_ua_tool, n_ua_rare = check_user_agents(recs)
    n_bodies, n_links = attach_links(recs, attach)
    if not recs:
        print("[-] No email to analyze.")
        return
    mark_visits(recs)
    score_mails(recs)

    count = Counter(r["label"] for r in recs)
    n_sig = sum(1 for r in recs if r["score"] > 0)
    n_vis = sum(1 for r in recs if r.get("n_visited"))
    print(f"\n[+] {len(recs)} email(s) ({', '.join(f'{k}={v}' for k, v in count.most_common())}) | "
          f"{sum(len(r['atts']) for r in recs)} attachment(s) | {n_links} link(s) in {n_bodies} bodies")
    print(f"[+] Sending client (User-Agent/X-Mailer): {n_ua_tool} suspicious tool(s), "
          f"{n_ua_rare} unusual client(s) for the sender domain")
    print(f"[+] {n_sig} email(s) with at least one signal; {n_vis} with a link visited after receipt; "
          f"severity: {dict(Counter(r['sev'] for r in recs if r['score'] > 0))}")

    print_top_mails(recs, TOP_MAILS)
    print_link_domains(recs, TOP_LINK_DOMAINS)
    print_senders(recs, TOP_SENDERS)

    detail = DETAIL_MAILS
    if detail is None:
        detail = sys.stdin.isatty() and n_sig > 0 and \
            input("\nShow full details of emails with signals? [y/N]: ").strip().lower() == "y"
    if detail:
        print_mail_details(recs)
    if not OUT_DIR:
        print("[i] Full details (all emails, all links): re-run with --out <folder> or menu 'e'.")

    # Findings: one per email with a significant signal (the receiving internal host carries the score)
    for rec in recs:
        if rec["score"] < 2:
            continue
        src = rec["r"] if rec["kind"] == "in" else rec["o"]
        dst = rec["o"] if rec["kind"] == "in" else rec["r"]
        add_finding("2", rec["sev"], src, dst, "email_suspect",
                    f"{rec['label']} score={rec['score']} from={rec['from'] or rec['mf']} to={short_rcpt(rec['to'])} "
                    f"subject={cut(rec['subj'], 80)} :: {'; '.join(mail_reasons(rec))}",
                    format_ts(rec["ts"]) if rec["ts"] else "", rec["log"], rec["uid"])

    write_table("emails", ["ts", "header_date", "score", "severity", "direction", "uid", "src_ip", "dst_ip", "helo",
                           "origin_ip", "origin_name", "origin_source", "ip_path", "sending_client", "mail_from",
                           "from", "to", "cc", "subject", "reply_to", "attachments", "links", "flagged_links",
                           "visited_links", "worst_link", "reasons", "log"],
                [[format_ts(r["ts"]) if r["ts"] else "", fmt_mail_date(r["date"]) if r["date"] else "",
                  r["score"], r["sev"], r["label"], r["uid"], r["o"], r["r"], r["helo"],
                  r["orig_ip"], r["orig_name"], r["orig_src"], r["path"], r["ua"],
                  r["mf"], r["from"], r["to"], r["cc"], r["subj"], r["rt"],
                  "; ".join(f"{a[0]}|{a[1]}|{a[2]}|{a[3]}" for a in r["atts"]), len(r["links"]),
                  r.get("n_flagged", 0), r.get("n_visited", 0),
                  (worst_link(r) or {}).get("url", ""), "; ".join(mail_reasons(r)), r["log"]]
                 for r in sorted(recs, key=lambda x: (-x["score"], x["ts"]))])
    write_table("email_links", ["ts", "uid", "from", "subject", "url", "domain", "displayed_text", "severity",
                                "alerts", "whitelist", "visit_ts", "visit_ip", "visit_log", "file"],
                [[format_ts(r["ts"]) if r["ts"] else "", r["uid"], r["from"], r["subj"], l["url"], l["host"],
                  l["label"], l["sev"], "; ".join(l["flags"]), "yes" if l["wl"] else "",
                  format_ts(l["visit"][0]) if l["visit"] else "", l["visit"][1] if l["visit"] else "",
                  l["visit"][2] if l["visit"] else "", l["file"]]
                 for r in recs for l in r["links"].values()])


# ======================================================================
# WEB SUMMARY (http/ssl) WITH KEYWORD
# ======================================================================
def task_kw_uids(item):
    """uids of sessions whose HTTP host/URI, SNI or DNS query contains the keyword."""
    kind, path = item
    rx = CTX["kw_re"]
    cols = {"http": ["uid", "host", "uri"], "ssl": ["uid", "server_name"], "dns": ["uid", "query"]}[kind]
    out = set()
    for row in iter_zeek(path, cols):
        if rx.search(" ".join(v for k, v in row.items() if k != "uid" and v not in UNSET)):
            out.add(row.get("uid", ""))
    out.discard("")
    return out


def task_web(item):
    kind, path = item
    rx, wl = CTX.get("kw_re"), CTX["dom_wl"]
    cols = (["ts", "uid", "id.orig_h", "id.resp_h", "method", "host", "uri", "status_code"] if kind == "http"
            else ["ts", "uid", "id.orig_h", "id.resp_h", "server_name"])
    out = {}
    for row in iter_zeek(path, cols):
        if kind == "http":
            host = strip_port(row.get("host", "-").lower())
            uri, method, status = row.get("uri", "-"), row.get("method", "-"), row.get("status_code", "-")
            if host in UNSET:
                host = strip_port(uri.lower()) if method == "CONNECT" and uri not in UNSET else row.get("id.resp_h", "")
            uri = uri.split("?")[0]
        else:
            host = row.get("server_name", "-").lower()
            uri, method, status = "", "TLS", "-"
            if host in UNSET:
                continue
        if wl and match_host(host, wl):
            continue
        if rx and not rx.search(f"{host} {uri}"):
            continue
        key = (kind, row.get("id.orig_h", ""), row.get("id.resp_h", ""), method, host, uri)
        ts = to_float(row.get("ts"))
        a = out.get(key)
        if a is None:
            out[key] = [1, ts, ts, row.get("uid", ""), status, path]
        else:
            a[0] += 1
            if ts < a[1]:
                a[1], a[3], a[5] = ts, row.get("uid", ""), path
            a[2] = max(a[2], ts)
    return out


def phase_web(keyword=None, top=None, ask=True):
    title("WEB SUMMARY: source IP -> destination, host/URI, first/last seen (http.log + SNI from ssl.log)")
    keyword = keyword or CLI_KEYWORD
    if keyword is None and ask and sys.stdin.isatty():
        keyword = input("Keyword (host/URI/SNI, separated by |; empty = everything outside the whitelist): ").strip() or None
    top = top or DISPLAY_LIMIT
    items = [(k, p) for k in ("http", "ssl") for p in find_logs(k)]
    if not items:
        print("[!] No http.log / ssl.log found.")
        return
    kws = [k.strip() for k in keyword.split("|") if k.strip()] if keyword else None
    ctx = {"dom_wl": set() if kws else load_domain_whitelist()}
    if kws:
        ctx["kw"] = kws
        print(f"[*] Filter: {kws} (domain whitelist disabled for the search)")
    merged = {}
    for r in run_parallel(task_web, items, ctx):
        for k, v in r.items():
            cur = merged.get(k)
            if cur is None:
                merged[k] = v
            else:
                cur[0] += v[0]
                if v[1] < cur[1]:
                    cur[1], cur[3], cur[5] = v[1], v[3], v[5]
                cur[2] = max(cur[2], v[2])
    if not merged:
        print("[-] No results.")
        return
    per_host = defaultdict(lambda: [0, set(), 1e18, 0.0])
    for (kind, o, r, method, host, uri), (n, first, last, uid, st, log) in merged.items():
        h = per_host[host]
        h[0] += n
        h[1].add(o)
        h[2] = min(h[2], first)
        h[3] = max(h[3], last)
    print(f"\n[+] {len(merged)} combinations (src, dst, host, URI); {len(per_host)} distinct hosts")
    print("\n--- TOP HOSTS (requests, sources, first -> last seen) ---")
    for host, (n, srcs, first, last) in sorted(per_host.items(), key=lambda x: -x[1][0])[:15]:
        print(f"  {host:<50} x{n:<6} {len(srcs)} src  {format_ts(first)} -> {format_ts(last)}")
    print(f"\n--- DETAILS (sorted by first seen, max {top}) ---")
    print(f"{'first seen':<20} {'last seen':<20} {'count':>5}  src -> dst | request | status | uid")
    rows = []
    for i, ((kind, o, r, method, host, uri), (n, first, last, uid, st, log)) in enumerate(
            sorted(merged.items(), key=lambda x: x[1][1])):
        shown = display_url(host, uri) if kind == "http" else f"TLS SNI {host}"
        req = shown if shown.startswith(method) else f"{method} {shown}"
        rows.append([format_ts(first), format_ts(last), n, o, r, method, shown, st, uid, log])
        if i < top:
            print(f"{format_ts(first):<20} {format_ts(last):<20} {n:>5}  {o} -> {r} | {req} | {st} | {uid}")
    if len(merged) > top:
        print(f"  ... {len(merged) - top} more lines in the export (--out).")
    if kws:
        print("\n[i] For the full chain of a session: --correlate <IP|uid>  (or menu c with the same keyword).")
    write_table("web_summary", ["first_seen", "last_seen", "count", "src_ip", "dst_ip", "method", "request",
                                 "status", "uid", "log"], rows)


# ======================================================================
# PHASE 9: PROXY / HTTP (CONNECT destinations, per-host beaconing)
# ======================================================================
PROXY_COLS = ["ts", "uid", "id.orig_h", "id.resp_h", "method", "host", "uri"]


def task_http_hosts(path):
    """(client, host, CONNECT|HTTP) -> [timestamp sample, server/proxy IPs, first uid, count, first ts]."""
    wl, iocs = CTX["dom_wl"], CTX["ioc_hosts"]
    out = {}
    for row in iter_zeek(path, PROXY_COLS):
        method = row.get("method", "-")
        raw = row.get("host", "-")
        if method == "CONNECT":
            uri = row.get("uri", "-")
            raw = uri if uri not in UNSET else raw
        if raw in UNSET:
            continue
        host = strip_port(raw.lower()).rstrip(".")
        if not match_host(host, iocs) and match_host(host, wl):
            continue
        typ = "CONNECT" if method == "CONNECT" else "HTTP"
        key = (row.get("id.orig_h", ""), host, typ)
        ts = to_float(row.get("ts"))
        rec = out.get(key)
        if rec is None:
            rec = out[key] = [ts_new(ts), set(), row.get("uid", ""), 1, ts]
        else:
            ts_add(rec[0], ts)
            rec[3] += 1
        if len(rec[1]) < 5:
            rec[1].add(row.get("id.resp_h", ""))
        if ts < rec[4]:
            rec[4], rec[2] = ts, row.get("uid", "")
    return out


def phase_proxy(top=30):
    phase = "9"
    reset_findings(phase)
    title("PHASE 9: HTTP / proxy: CONNECT destinations & per-host beaconing (http.log)")
    files = find_logs("http")
    if not files:
        print("[!] No http.log found.")
        return
    ctx = build_ctx()
    ioc = ctx["ioc_hosts"]
    merged = {}
    for r in run_parallel(task_http_hosts, files, ctx):
        for k, v in r.items():
            cur = merged.get(k)
            if cur is None:
                merged[k] = v
            else:
                cur[0] = ts_merge(cur[0], v[0])
                cur[1] |= v[1]
                cur[3] += v[3]
                if v[4] < cur[4]:
                    cur[4], cur[2] = v[4], v[2]

    hosts = {}
    for (o, host, typ), (sample, resp, uid, n, first) in merged.items():
        last = sample[4]
        h = hosts.get((host, typ))
        if h is None:
            h = hosts[(host, typ)] = [0, Counter(), set(), first, last, uid]  # h[1]: client -> request count
        h[0] += n
        h[1][o] += n
        h[2] |= resp
        if first < h[3]:
            h[3], h[5] = first, uid
        h[4] = max(h[4], last)

    # Beaconing computed before printing the destinations so they can be tagged [BCN]
    beacons = []
    for (o, host, typ), (sample, resp, uid, n, first) in merged.items():
        st = beacon_stats(sample)
        if st:
            beacons.append((o, host, typ, st, resp, uid))
    beacons.sort(key=lambda x: (x[2] != "CONNECT", -x[3][0]))
    beacon_hosts = {host for o, host, typ, *_ in beacons if typ == "CONNECT"}

    def tags(host, n, clients):
        t = []
        if match_host(host, ioc):
            t.append("[IOC]")
        if host in beacon_hosts:
            t.append("[BCN]")
        if clients and max(clients.values()) >= PROXY_VOLUME_MIN:
            t.append("[VOL]")
        if len(clients) == 1:
            t.append("[rare]")
        return "".join(t)

    def max_client(clients):
        return max(clients.values()) if clients else 0

    rows = [(host, v) for (host, typ), v in hosts.items() if typ == "CONNECT"]
    # sort: IOC, then beaconing/volume, then requests of the most active client
    rows.sort(key=lambda x: (match_host(x[0], ioc) is None,
                             not (x[0] in beacon_hosts or max_client(x[1][1]) >= PROXY_VOLUME_MIN),
                             -max_client(x[1][1])))
    print(f"\n--- CONNECT DESTINATIONS ({len(rows)} non-whitelisted hosts; sort: IOC, then beaconing/volume, "
          f"then requests of the most active client) ---")
    if not rows:
        print("[-] No CONNECT request (no explicit proxy, or proxy not visible to the sensor).")
    else:
        print(f"  Tags: [IOC] IOC domain | [BCN] beaconing from at least one client | [VOL] >={PROXY_VOLUME_MIN} "
              f"requests from at least one client | [rare] single client")
        print(f" {'':<16} {'Host':<42} {'CONNECT':>7} {'Clients':>7} {'Max/cl.':>7}  {'First seen':<20} {'Last seen':<20} Proxy")
        print(" " + "-" * 136)
    for host, (n, clients, proxies, first, last, uid) in rows[:top]:
        hit = match_host(host, ioc)
        flag = tags(host, n, clients)
        print(f" {flag:<16} {cut(host, 42):<42} {n:>7} {len(clients):>7} {max_client(clients):>7}  "
              f"{format_ts(first):<20} {format_ts(last):<20} {','.join(sorted(proxies))}")
        if "[VOL]" in flag and not hit:
            for c, k in clients.items():
                if k < PROXY_VOLUME_MIN:
                    continue  # only clients above the threshold are reported
                add_finding(phase, "medium", c, host, "connect_volume",
                            f"CONNECT {host} x{k} ({len(clients)} client(s), {format_ts(first)} -> {format_ts(last)})",
                            format_ts(first), "", uid)
        shown = ", ".join(f"{c} ({k})" for c, k in clients.most_common(PROXY_CLIENTS_SHOWN))
        more = f" +{len(clients) - PROXY_CLIENTS_SHOWN} more" if len(clients) > PROXY_CLIENTS_SHOWN else ""
        print(f" {'':<6} ↳ clients : {shown}{more} | uid={uid}")
        if hit:
            for c in clients:
                add_finding(phase, "high", c, host, "ioc_connect", f"CONNECT {host} [{ioc[hit]}] x{n}",
                            format_ts(first), "", uid)
    if len(rows) > top:
        print(f"  ... {len(rows) - top} more host(s) in the export (--out).")
    write_table("proxy_connect", ["tags", "host", "connect_count", "client_count", "clients", "first_seen", "last_seen",
                                  "proxy", "ioc", "uid"],
                [[tags(h, n, c), h, n, len(c), " ".join(f"{ip}({k})" for ip, k in c.most_common()), format_ts(f),
                  format_ts(l), " ".join(sorted(p)),
                  ioc.get(match_host(h, ioc) or "", ""), u] for h, (n, c, p, f, l, u) in rows])

    print(f"\n--- HTTP BEACONING per (client, host): {len(beacons)} candidate(s), CONNECT first "
          f"(>={BEACON_MIN_CONN} requests, jitter ±{int(BEACON_JITTER * 100)}%) ---")
    if not beacons:
        print("[-] None. A long-lived CONNECT tunnel generates few requests: "
              "check the Max/cl. column above and the correlation (menu c or --keyword <host>).")
    for o, host, typ, (cnt, med, ratio, first, last), resp, uid in beacons[:top]:
        via = f" via proxy {','.join(sorted(resp))}" if any(is_private_ip(x) for x in resp) else ""
        tag = "[IOC]" if match_host(host, ioc) else "[!]"
        print(f"  {tag} {o} ---> {typ} {host} x{cnt} | median interval {med:.0f}s | regularity {ratio:.0%} "
              f"| {format_ts(first)} -> {format_ts(last)}{via} | uid={uid}")
        add_finding(phase, "high", o, host, "beacon_http",
                    f"{typ} {host} x{cnt} median={med:.0f}s regularity={ratio:.0%}{via}", format_ts(first), "", uid)


# ======================================================================
# MENU & CLI
# ======================================================================
PHASES = {
    "0": ("Network mapping", phase0_cartography),
    "1": ("Discovery & threat intel (IOC IPs/domains/DNS/SNI, User-Agents)", phase1_discovery),
    "2": ("Spearphishing: email triage + downloads", phase2_spearphishing),
    "3": ("C2: non-standard ports + beaconing", phase3_c2),
    "4": ("Lateral movement + fan-out", phase4_lateral_movement),
    "5": ("Leaks / sensitive files (SMB)", phase5_leak_hunting),
    "6": ("DNS anomalies (tunneling / DGA)", phase6_dns),
    "7": ("Exfiltration & scans", phase7_exfil_scan),
    "8": ("TLS: JA3/JA3S & certificates", phase8_tls),
    "9": ("Proxy / HTTP: CONNECT destinations & per-host beaconing", phase_proxy),
}
TOOLS = {
    "s": ("Web summary (src/dst IPs, host/URI, first/last seen) + keyword", phase_web),
    "t": ("Triage of remaining public IPs (with/without a name)", phase_triage),
}
AUTO_PHASES = list(PHASES)  # 0 to 9


def run_all(out_dir):
    """Option e / --phase all: phases 0-9 + web summary, per-host score and full export."""
    global OUT_DIR
    OUT_DIR = out_dir or OUT_DIR or "./report"
    print(f"[*] Full run, exports in {OUT_DIR}")
    for k in AUTO_PHASES:
        PHASES[k][1]()
    phase_web(ask=False)  # no keyword: all web traffic outside the whitelist (keyword via --keyword)
    rows = print_host_scores()
    export_findings(OUT_DIR, rows)


def main_menu(out_dir=None):
    global _CONN_CACHE, _X509_CACHE, _NAMES_CACHE, OUT_DIR
    OUT_DIR = out_dir
    while True:
        print("\n" + "=" * 54 + f"\n     ZEEK FORENSICS HUNTER v{VERSION}\n" + "=" * 54)
        print(f"Root: {LOG_ROOT} | Workers: {JOBS}")
        for k, (name, _) in PHASES.items():
            print(f"{k}. Phase {k}: {name}")
        print("c. Correlation by uid / host (interactive)")
        for k, (name, _) in TOOLS.items():
            print(f"{k}. {name}")
        print("w. Whitelists & IOC ingestion\n"
              "e. Phases 0-9 + s + per-host score + export\n"
              "r. Re-index the tree / clear caches\nq. Quit")
        try:
            choice = input("\nChoice: ").strip().lower()
        except EOFError:
            break
        if choice in PHASES:
            PHASES[choice][1]()
        elif choice in TOOLS:
            TOOLS[choice][1]()
        elif choice == "c":
            correlate(out_dir=OUT_DIR)
        elif choice == "w":
            manage_whitelists()
        elif choice == "e":
            run_all(OUT_DIR)
        elif choice == "r":
            _CONN_CACHE = _X509_CACHE = _NAMES_CACHE = None
            get_index(force=True)
        elif choice == "q":
            break


def main():
    global LOG_ROOT, JOBS, CLI_EXTS, CLI_KEYWORD, CLI_MAIL_DIR, OUT_DIR, DETAIL_MAILS
    ap = argparse.ArgumentParser(description=f"Zeek Forensics Hunter v{VERSION}")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    ap.add_argument("--root", help="Zeek log root (default: $ZEEK_LOG_ROOT, else ./zeek_output)")
    ap.add_argument("-j", "--jobs", type=int, help="number of processes (default: CPU count)")
    ap.add_argument("--phase", nargs="+", choices=list(PHASES) + list(TOOLS) + ["all"],
                    help="non-interactive run: 0-9, s (web summary), t (IP triage); "
                         "all = 0-9 + s + per-host score + export (same as menu e)")
    ap.add_argument("--ext", help="extensions for phase 2, e.g. '.exe|.zip|.dll'")
    ap.add_argument("--out", help="CSV/JSON export folder for findings / timelines")
    ap.add_argument("--ingest", help="Abuse.ch (URLhaus) ZIP/CSV to ingest, then exit")
    ap.add_argument("--ingest-tls", help="SSLBL CSV (JA3 or certificates) to ingest, then exit")
    ap.add_argument("--learn-whitelist", action="store_true",
                    help="learn the IP whitelist from dns/ssl/http and whitelist.txt")
    ap.add_argument("--import-ranges", metavar="FILE", help="import official IP ranges (JSON/text)")
    ap.add_argument("--tags", nargs="+", help="service filter for --import-ranges (e.g. S3 EC2)")
    ap.add_argument("--correlate", metavar="IP|UID", help="uid-correlated timeline for a host or a uid")
    ap.add_argument("--keyword", help="keyword (separated by |): web summary (s), or correlation when used alone")
    ap.add_argument("--mail-dir", help="folder of extracted email bodies (smtp-<fuid>) or .eml (phase 2) "
                                       f"[default: {DEFAULT_MAIL_DIR}, else --root]")
    ap.add_argument("--detail", action="store_true", help="phase 2: also print per-email details")
    ap.add_argument("--since", help="UTC window start (e.g. '2024-05-01 08:00')")
    ap.add_argument("--until", help="UTC window end")
    ap.add_argument("--limit", type=int, default=60, help="max number of sessions shown (default 60)")
    ap.add_argument("--with-events", action="store_true",
                    help="keep only sessions with http/dns/ssl/files/... events")
    args = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    if args.root:
        LOG_ROOT = args.root
    if args.jobs:
        JOBS = max(1, args.jobs)
    CLI_KEYWORD = args.keyword
    CLI_MAIL_DIR = args.mail_dir
    OUT_DIR = args.out
    if args.detail:
        DETAIL_MAILS = True
    elif args.phase:
        DETAIL_MAILS = False
    if args.ext:
        CLI_EXTS = [e.strip() for e in args.ext.split("|") if e.strip()]

    init_environment()
    reload_ip_whitelist()

    if args.ingest:
        ingest_abuse(args.ingest)
        return
    if args.ingest_tls:
        ingest_tls_iocs(args.ingest_tls)
        return
    if args.import_ranges:
        import_ranges(args.import_ranges, args.tags)
        return
    if not os.path.isdir(LOG_ROOT):
        print(f"[!] Zeek log root not found: {LOG_ROOT}\n"
              "    Point --root (or the ZEEK_LOG_ROOT variable) to the output folder of run_zeek.sh.")
        sys.exit(1)
    if args.learn_whitelist:
        learn_whitelist()
        return
    if args.correlate or (args.keyword and not args.phase):
        correlate(args.correlate, args.since, args.until, args.limit, args.out, args.with_events,
                         args.keyword)
        return
    if args.phase:
        if "all" in args.phase:  # "all" + extra tools (e.g. --phase all t)
            run_all(args.out)
            for k in args.phase:
                if k in TOOLS and k != "s":
                    TOOLS[k][1]()
            return
        for ph in args.phase:
            (PHASES.get(ph) or TOOLS[ph])[1]()
        rows = print_host_scores()
        if args.out:
            export_findings(args.out, rows)
        return
    main_menu(args.out)


if __name__ == "__main__":
    main()
