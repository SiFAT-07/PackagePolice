#!/usr/bin/env python3
"""
PackagePolice - Universal Data Collection Script (v5.0 "Universal Edition")
Base: teammate's safe_collect.py v4.9.6 (recursive dep trees, AST-based
install-script danger detection, disposable-email maintainer check, resume
tracking by exact version - all retained unchanged, this was the stronger
of the two prototype scripts).

CHANGES FROM v4.9.6, each justified:

1. --limit N flag added to main(). v4.9.6 could resume, but couldn't cap
   how many NEW packages a single run processes. Needed so a shared
   4,000-6,000 package master_list.csv can be worked through in batches
   of e.g. 400, across many sessions/people, without ever re-touching
   already-collected packages.

2. Output paths moved from Path.home()/"packagepolice"/... to paths
   relative to this script's location inside the repo (REPO_ROOT below).
   v4.9.6 wrote the dataset outside the git repo entirely, which meant
   `git add data/dataset.csv` from the repo root would never find it.
   Everything now lands inside the repo (data/, quarantine/, raw/, logs/)
   so the existing "git push -> teammate git pull" sharing workflow
   actually works without manual file-moving.

3. signal5_semantic_embedding() renamed to signal5_code_analysis().
   Despite the name, this function has never produced a semantic
   embedding (no model, no vector) - it's AST-based risky-call counting
   and obfuscation flags, which is genuinely useful but is a different
   thing from CodeBERT embeddings. Renamed so nobody mistakes this
   column set for the real semantic signal. Real embeddings are a
   separate follow-up script - see extract_semantic_embeddings.py and
   the accompanying guide.

4. Added a doc-comment on total_dependency_count clarifying it counts
   TRANSITIVE dependencies only (not including the direct ones, which
   are already in direct_dependency_count). The column itself is
   unchanged - this is documentation only, so existing collected rows
   stay valid and the schema everyone commits against doesn't move.

5. Dataset filename dropped the "_v4" suffix -> data/dataset.csv. This
   is now the one shared, git-committed file every teammate appends to
   with the same script, satisfying "rows/columns stay identical."

Everything else (recursive dependency walking, AST setup.py danger
detection, disposable-email check, GitHub rate-limit awareness, zip-slip
+ symlink-safe extraction, metadata_completeness/training_eligible
leakage guards) is v4.9.6's design, unchanged.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import tarfile
import time
import zipfile
import tempfile
import ast
import configparser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
import urllib.parse

# Try to import tomllib for pyproject.toml parsing
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

# Try to import esprima for JS AST parsing
try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False

import requests

# ================ CONFIGURATION ================
# CHANGED (see header note #2): paths are now relative to this script's
# location in the repo, not the user's home directory. Assumes this file
# lives at scripts/01_data_collection/universal_collect.py - adjust the
# two ".parent" calls below if you move it.
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent

QUARANTINE_ROOT = REPO_ROOT / "quarantine"
DATASET_CSV = REPO_ROOT / "data" / "dataset.csv"
RAW_METADATA_DIR = REPO_ROOT / "raw" / "metadata"
RAW_GITHUB_DIR = REPO_ROOT / "raw" / "github_profiles"
RAW_DEP_TREE_DIR = REPO_ROOT / "raw" / "dependency_trees"
LOGS_DIR = REPO_ROOT / "logs"
COLLECTION_LOG = LOGS_DIR / "collection_log.csv"
MALICIOUS_LIST_FILE = REPO_ROOT / "data" / "malicious_list.txt"
ESPRIMA_PARSE_LOG = LOGS_DIR / "esprima_parse_failures.csv"

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"
GITHUB_API = "https://api.github.com"
NPM_DOWNLOADS_API = "https://api.npmjs.org/downloads/point"

REQUEST_DELAY = 0.3
MAX_DEPENDENCY_DEPTH = 3
MAX_RETRIES = 3
RETRY_BACKOFF = 2
MAX_ARCHIVE_SIZE_MB = 200

SUSPICIOUS_KEYWORDS = [
    'eval', 'exec', 'base64', 'subprocess', 'os.system', 'curl', 'wget',
    'requests.get', 'fetch(', 'child_process', 'chmod', 'sudo', 'crypto',
    'b64decode', '__import__', 'execfile', 'system(', 'popen'
]

RISKY_PY_FUNCS = {
    'eval', 'exec', 'compile', '__import__', 'execfile', 'input',
    'os.system', 'os.popen', 'os.open', 'io.open', 'subprocess.Popen',
    'subprocess.call', 'subprocess.check_output', 'subprocess.run'
}
RISKY_JS_FUNCS = {'eval', 'exec', 'child_process.exec',
                  'child_process.spawn', 'fs.readFile', 'fs.writeFile'}

SENSITIVE_PATTERNS = [r'\benv\b', r'\bos\.environ\b', r'\bprocess\.env\b', r'/etc/passwd', r'/etc/shadow']

# Base disposable domain list — will be updated at runtime if possible
_DISPOSABLE_DOMAINS_BASE = {
    'tempmail.com', 'guerrillamail.com', '10minutemail.com',
    'mailinator.com', 'temp-mail.org', 'throwaway.email',
    'fakeinbox.com', 'trashmail.com', 'yopmail.com', 'spamgourmet.com',
    'tempmail.net', 'mailnator.com', 'mailcatch.com', 'mintemail.com',
    'spambox.us', 'trash2009.com', 'trashymail.com', 'tyldd.com',
    'uggsrock.com', 'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org',
    'wh4f.org', 'whyspam.me', 'willselfdestruct.com', 'winemaven.info',
    'wronghead.com', 'wuzup.net', 'xagloo.com', 'xemaps.com', 'xents.com',
    'xmaily.com', 'xoxy.net', 'yep.it', 'yogamaven.com', 'yopmail.fr',
    'yopmail.net', 'ypmail.webarnak.fr.eu.org', 'yuurok.com',
    'zehnminutenmail.de', 'zippymail.info', 'zoaxe.com', 'zoemail.org',
    'tempmail.org', 'mailna.co', 'mailna.me', 'mailnator.com',
    'mailnesia.com', 'mailshell.com', 'mailtemp.org', 'malahov.com',
    'meltmail.com', 'messagebeamer.de', 'mit-temp-mail.de', 'monemail.com',
    'monmail.me', 'msa.minsmail.com', 'mt2009.com', 'mx0.wwwnew.eu',
    'my10minutemail.com', 'mytrashmail.com', 'neomailbox.com', 'nepwk.com',
    'nervmich.net', 'nervtmich.net', 'netmails.com', 'netmails.net',
    'neverbox.com', 'nice-4-you.com', 'nincsmail.hu', 'nmail.cf',
    'no-spam.ws', 'nobugmail.com', 'nospamfor.us', 'nospammail.net',
    'notmailinator.com', 'nowmymail.com', 'nurfuerspam.de', 'objectmail.com',
    'obobbo.com', 'odnorazovoe.ru', 'one-time.email', 'oneoffemail.com',
    'oneoffmail.com', 'onetempmail.com', 'online.ms', 'ootmail.com',
    'ordinaryamerican.net', 'otherinbox.com', 'ourklips.com', 'outlawspam.com',
    'over-the-rainbow.com', 'p71ce1m.net', 'pepbot.com', 'petrol.tk',
    'pimpedup.net', 'pjjkp.com', 'plexolan.de', 'poczta.onet.pl',
    'pokemail.net', 'pooae.com', 'poofy.org', 'pookmail.com', 'privacy.net',
    'proxymail.eu', 'prtnx.com', 'putthisinyourspamdatabase.com', 'pwrby.com',
    'quickinbox.com', 'quickmail.nl', 'rcpt.at', 're-gister.com', 'reallymymail.com',
    'recyclemail.dk', 'redfeathercrow.com', 'regbypass.com', 'regspaces.com',
    'rejectmail.com', 'reliable-mail.com', 'rhyta.com', 'rmqkr.net',
    'rppkn.com', 'rtrtr.com', 's0ny.net', 'safe-mail.net', 'safersignup.com',
    'safetymail.info', 'safetypost.de', 'sandwhich.net', 'saynotospams.com',
    'selfdestructingmail.com', 'sendspamhere.com', 'senseless-entertainment.com',
    'server.ms', 'sharklasers.com', 'shut.ws', 'sin.cl', 'sinnlos-mail.de',
    'slapsmail.net', 'slaskpost.se', 'smaakt.na', 'smashmail.de', 'snakemail.com',
    'sneakemail.com', 'socks.mailinator.com', 'sofimail.com', 'solvemail.info',
    'spam.la', 'spam.su', 'spam4life.com', 'spamail.de', 'spamarrest.com',
    'spambob.com', 'spambob.net', 'spambob.org', 'spambog.com', 'spambog.de',
    'spambog.net', 'spambog.ru', 'spambooger.com', 'spambox.info', 'spambox.irish',
    'spambox.us', 'spamcero.com', 'spamcon.org', 'spamcorptastic.com', 'spamcowboy.com',
    'spamcowboy.net', 'spamcowboy.org', 'spamday.com', 'spamdecoy.net',
    'spamex.com', 'spamfighter.com', 'spamfree24.com', 'spamfree24.de',
    'spamfree24.eu', 'spamfree24.info', 'spamfree24.net', 'spamfree24.org',
    'spamgoes.in', 'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org',
    'spamhereplease.com', 'spamhole.com', 'spamify.com', 'spaminator.de',
    'spamkill.info', 'spaml.com', 'spaml.de', 'spammotel.com', 'spamobox.com',
    'spamoff.com', 'spamsalad.com', 'spamslicer.com', 'spamspot.com',
    'spamstack.net', 'spamthis.co.uk', 'spamthisplease.com', 'spamtrail.com',
    'spamtrap.net', 'spamwc.com', 'spamwc.de', 'speed.1s.fr', 'sperma.net',
    'spikio.com', 'spoofmail.de', 'squizzy.de', 'sry.li', 'stop-my-spam.com',
    'stuffmail.de', 'subdomain.com', 'supergreatmail.com', 'supermailer.jp',
    'superrito.com', 'sweetxxx.de', 'swift-mail.net', 'teewars.org', 'teleworm.com',
    'temp-mail.com', 'temp-mail.de', 'temp-mail.net', 'temp-mail.org',
    'temp-mail.ru', 'temp.0rg.eu', 'temp1.info', 'temp2.biz', 'temp2.info',
    'temp3.net', 'tempmail.de', 'tempmail.eu', 'tempmail.info', 'tempmail.me',
    'tempmail.us', 'tempmail2.com', 'tempmaildemo.com', 'tempmailer.com',
    'tempomail.fr', 'temporarily.de', 'temporario.email', 'temporary-email.com',
    'temporary-email.net', 'temporary-email.org', 'temporary-mail.com',
    'temporary-mail.net', 'temporary-mail.org', 'temporaryemail.us',
    'temporarymail.com', 'temporarymail.net', 'temporarymail.org',
    'temporrayemail.com', 'temporryemail.com', 'tempthe.net', 'thankyou2010.com',
    'thc.st', 'thebat.ch', 'theinternetemail.com', 'thelimestones.com',
    'thismail.net', 'throwam.com', 'throwaway.email', 'throwawayable.com',
    'throwawaymail.com', 'throwawaymail.net', 'throwawaymail.org',
    'throwawmail.com', 'throya.com', 'tinfoil.email', 'tmail.com',
    'tmail.com.tr', 'tmail.li', 'tmail.ws', 'tmailinator.com', 'tmmail.net',
    'toiea.com', 'tokem.co', 'tom.com', 'top101.de', 'topmail-files.com',
    'topmail.com.ar', 'topranklist.de', 'tormail.org', 'toss.pw',
    'trash-2000.com', 'trash-mail.com', 'trash-mail.de', 'trash200.com',
    'trash2002.com', 'trash2003.com', 'trash2004.com', 'trash2005.com',
    'trash2006.com', 'trash2007.com', 'trash2008.com', 'trash2009.com',
    'trash2010.com', 'trash2011.com', 'trashcanmail.com', 'trashdevil.com',
    'trashdevil.de', 'trashemail.de', 'trashemail.org', 'trashmail.at',
    'trashmail.com', 'trashmail.de', 'trashmail.me', 'trashmail.net',
    'trashmail.org', 'trashmail.ws', 'trashmailer.com', 'trashymail.net',
    'trbvm.com', 'trbvn.com', 'trbvo.com', 'trinidad.net', 'tryalert.com',
    'twinmail.de', 'tyldd.com', 'uggsrock.com', 'umail.net', 'unknownoops.com',
    'upliftnow.com', 'ureach.com', 'urgentmail.biz', 'us.af', 'us.to',
    'used-product.com', 'uu.gl', 'uymail.com', 'veryfast.biz', 'verymail.biz',
    'veryrealemail.com', 'viditag.com', 'vip.50gram.com', 'vipmail.name',
    'vipmail.pw', 'visa.com', 'vixlet.com', 'vmailing.info', 'vrmtr.com',
    'vsimcard.com', 'vubby.com', 'wapda.org', 'wazabi.club', 'wbml.net',
    'web-mail.com.ar', 'web2mail.com', 'webemail.me', 'webm4il.info',
    'webmail.kolumbus.fi', 'webmailv.com', 'webname.org', 'webox.com',
    'weg-werf-email.de', 'wegwerf-email.net', 'wegwerfadresse.de',
    'wegwerfmail.com', 'wegwerfmail.net', 'wegwerfmail.org', 'wegwerpmailadresse.de',
    'wegwrfmail.de', 'wegwrfmail.net', 'wegwrfmail.org', 'wh4f.com',
    'wh4f.net', 'whsot.net', 'wickmail.net', 'wilemail.com', 'willhackforfood.biz',
    'willselfdestruct.com', 'winemaven.info', 'wn8t.com', 'wokcy.com',
    'wonmug.com', 'wopr.com', 'worldbreak.com', 'wow.com', 'wowmail.com',
    'wwjmp.com', 'xagloo.com', 'xemaps.com', 'xents.com', 'xmaily.com',
    'xoxy.net', 'xrap.de', 'xrho.com', 'xuno.com', 'yabai.com',
    'yep.it', 'yogamaven.com', 'yopmail.com',
    'yopmail.fr', 'yopmail.net', 'ypmail.webarnak.fr.eu.org', 'yuurok.com',
    'zehnminutenmail.de', 'zippymail.info', 'zoaxe.com', 'zoemail.com',
    'zoemail.net', 'zoemail.org', 'zombie-hive.com', 'zomg.info', 'zymuying.com'
}

KNOWN_ZIP_PASSWORDS = [b'infected']

FIELD_NAMES = [
    'package_name', 'version', 'ecosystem', 'label', 'sha256', 'data_source',
    'extraction_skipped',
    'metadata_completeness',
    'training_eligible',
    'author_name', 'author_email', 'maintainers', 'description', 'license',
    'homepage', 'repository_url', 'version_count', 'latest_version',
    'first_release_date', 'last_release_date', 'package_size_kb', 'keywords',
    'has_description', 'has_license', 'has_homepage', 'npm_download_count',
    'direct_dependency_count', 'total_dependency_count', 'max_dependency_depth',
    'has_malicious_dependency', 'top_dependencies', 'dependency_tree_file',
    'maintainer_email_domain_checked', 'is_disposable_email', 'github_repo_owner',
    'repo_stars', 'repo_forks', 'repo_open_issues', 'maintainer_github_followers',
    'maintainer_github_account_age_days',
    'maintainer_other_packages_count', 'maintainer_other_packages_unchecked',
    'has_github_repo', 'github_contributors_count',
    'has_install_script', 'install_script_line_count', 'install_script_byte_length',
    'suspicious_keyword_count', 'suspicious_keywords_found',
    'flag_internet_call', 'flag_system_command', 'flag_download_run',
    'flag_sensitive_read', 'install_script_preview',
    'has_setup_py', 'has_pyproject_toml', 'has_setup_cfg',
    'source_file_count', 'total_lines_of_code', 'file_extensions',
    'risky_function_calls_total', 'risky_function_calls_detail',
    'obfuscation_indicators', 'has_python_code', 'has_javascript_code',
    'js_ast_parse_success'
]

# ================ GLOBAL CACHES & HELPERS ================
_deps_cache: Dict[Tuple[str, str, str], Dict] = {}
_package_meta_cache: Dict[Tuple[str, str, str], Dict] = {}
_github_rate_limit_remaining = None
_DISPOSABLE_DOMAINS: Set[str] = set()


# ================ SAFE FILENAME HELPERS ================
def safe_filename(name: str) -> str:
    """Sanitize a package name for filesystem use (scoped npm packages)."""
    return name.replace('@', '').replace('/', '-')


# ================ DISPOSABLE DOMAINS ================
def update_disposable_domains() -> Set[str]:
    global _DISPOSABLE_DOMAINS
    if _DISPOSABLE_DOMAINS:
        return _DISPOSABLE_DOMAINS
    try:
        url = "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            fetched = set(resp.json())
            _DISPOSABLE_DOMAINS = fetched
            print(f"[INFO] Loaded {len(fetched)} disposable domains from remote source.")
            return _DISPOSABLE_DOMAINS
    except Exception:
        pass
    _DISPOSABLE_DOMAINS = _DISPOSABLE_DOMAINS_BASE.copy()
    print(f"[INFO] Using hardcoded fallback: {len(_DISPOSABLE_DOMAINS)} disposable domains.")
    return _DISPOSABLE_DOMAINS


def is_disposable_email(email: Optional[str]) -> bool:
    if not email or '@' not in email:
        return False
    domain = email.split('@')[1].lower().strip()
    domains = update_disposable_domains()
    if domain in domains:
        return True
    for d in domains:
        if domain.endswith('.' + d):
            return True
    return False


# ================ BASIC HELPERS ================
def ensure_dirs():
    for d in [QUARANTINE_ROOT, DATASET_CSV.parent, RAW_METADATA_DIR,
              RAW_GITHUB_DIR, RAW_DEP_TREE_DIR, LOGS_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def init_log():
    if not COLLECTION_LOG.exists():
        with open(COLLECTION_LOG, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'ecosystem', 'package_name', 'version',
                             'label', 'status', 'error_message', 'duration_seconds'])
    if not ESPRIMA_PARSE_LOG.exists():
        with open(ESPRIMA_PARSE_LOG, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'package_name', 'version', 'file_path', 'error'])


def log_entry(eco: str, pkg: str, ver: str, label: str, status: str,
              error: str = '', duration: float = 0):
    with open(COLLECTION_LOG, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().isoformat(), eco, pkg, ver,
                         label, status, error[:500], f"{duration:.2f}"])


def log_esprima_failure(pkg: str, ver: str, file_path: str, error: str):
    with open(ESPRIMA_PARSE_LOG, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().isoformat(), pkg, ver, file_path, error[:200]])


def save_raw_json(data: Any, dest_dir: Path, filename: str) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / filename
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    return path


def safe_extract(archive_path: Path, dest_dir: Path, zip_password: Optional[bytes] = None) -> bool:
    size_mb = archive_path.stat().st_size / (1024 * 1024)
    if size_mb > MAX_ARCHIVE_SIZE_MB:
        print(f"  [SKIP] Archive too large ({size_mb:.1f}MB > {MAX_ARCHIVE_SIZE_MB}MB limit)")
        return False

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    def is_within_dest(member_path: Path) -> bool:
        try:
            member_path.resolve().relative_to(dest_resolved)
            return True
        except ValueError:
            return False

    if archive_path.suffix == ".tgz" or (
        len(archive_path.suffixes) >= 2
        and archive_path.suffixes[-2] == ".tar"
        and archive_path.suffixes[-1] in [".gz", ".bz2", ".xz"]
    ):
        mode_map = {".gz": "r:gz", ".bz2": "r:bz2", ".xz": "r:xz"}
        mode = mode_map.get(archive_path.suffixes[-1], "r")
        try:
            with tarfile.open(archive_path, mode) as tf:
                for member in tf.getmembers():
                    if member.issym() or member.islnk():
                        print(f"  [SKIP] Symlink/hardlink skipped: {member.name}")
                        continue
                    if member.size > 50 * 1024 * 1024:
                        print(f"  [SKIPPED] {member.name} too large ({member.size / 1024 / 1024:.1f}MB)")
                        continue
                    target = dest_dir / member.name
                    if not is_within_dest(target):
                        print(f"[SKIPPED unsafe path] {member.name}")
                        continue
                    tf.extract(member, dest_dir, set_attrs=False)
        except tarfile.TarError as e:
            print(f"  [WARN] Failed to extract tar: {e}")
    elif archive_path.suffix in (".zip", ".whl"):
        passwords_to_try = [zip_password] if zip_password else []
        passwords_to_try.extend([p for p in KNOWN_ZIP_PASSWORDS if p not in passwords_to_try])
        passwords_to_try.append(None)

        extracted = False
        last_error = None
        for pwd in passwords_to_try:
            try:
                with zipfile.ZipFile(archive_path) as zf:
                    test_name = zf.namelist()[0] if zf.namelist() else None
                    if test_name:
                        try:
                            zf.read(test_name, pwd=pwd)
                        except RuntimeError as e:
                            if 'password' in str(e).lower():
                                continue
                            raise
                    for name in zf.namelist():
                        target = dest_dir / name
                        if not is_within_dest(target):
                            print(f"[SKIPPED unsafe path] {name}")
                            continue
                        try:
                            zf.extract(name, dest_dir, pwd=pwd)
                        except RuntimeError as e:
                            if 'password' in str(e).lower():
                                raise RuntimeError(f"Incorrect password for {name} in {archive_path}")
                            raise
                    extracted = True
                    break
            except (zipfile.BadZipFile, RuntimeError) as e:
                last_error = e
                continue
            except Exception as e:
                last_error = e
                continue

        if not extracted and last_error:
            print(f"  [WARN] Failed to extract zip: {last_error}")
    else:
        print(f"[WARN] Unknown archive type: {archive_path.name}")
    return True


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_request(url: str, headers: Optional[Dict] = None, timeout: int = 30,
                 retry_count: int = 0) -> Optional[requests.Response]:
    global _github_rate_limit_remaining
    if _github_rate_limit_remaining is not None and _github_rate_limit_remaining <= 5:
        print(f"  [RATE] GitHub rate limit low ({_github_rate_limit_remaining}), waiting 60s...")
        time.sleep(60)
        _github_rate_limit_remaining = None
    time.sleep(REQUEST_DELAY)
    try:
        resp = requests.get(url, headers=headers or {}, timeout=timeout)
        if resp.status_code == 404:
            return None
        if 'github.com' in url:
            remaining = resp.headers.get('X-RateLimit-Remaining')
            if remaining:
                _github_rate_limit_remaining = int(remaining)
            if resp.status_code == 403 and 'rate limit' in resp.text.lower():
                if retry_count < MAX_RETRIES:
                    wait_time = RETRY_BACKOFF ** retry_count * 2
                    print(f"  [RATE] Hit GitHub limit, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    return safe_request(url, headers, timeout, retry_count + 1)
                else:
                    print(f"  [WARN] Rate limit exhausted for {url}")
                    return None
        resp.raise_for_status()
        return resp
    except requests.exceptions.RequestException as e:
        if retry_count < MAX_RETRIES and 'timeout' not in str(e).lower() and '404' not in str(e):
            wait_time = RETRY_BACKOFF ** retry_count
            print(f"  [RETRY] {e}, retrying in {wait_time}s...")
            time.sleep(wait_time)
            return safe_request(url, headers, timeout, retry_count + 1)
        print(f"  [WARN] Request failed: {url} - {e}")
        return None


def fetch_package_metadata(eco: str, name: str, version: Optional[str] = None) -> Optional[Dict]:
    cache_key = (eco, name, version or '')
    if cache_key in _package_meta_cache:
        return _package_meta_cache[cache_key]
    encoded_name = urllib.parse.quote(name, safe='')
    if eco == 'npm':
        if version:
            url = f"{NPM_REGISTRY}/{encoded_name}/{version}"
        else:
            url = f"{NPM_REGISTRY}/{encoded_name}"
    else:
        if version:
            url = f"{PYPI_REGISTRY}/{name}/{version}/json"
        else:
            url = f"{PYPI_REGISTRY}/{name}/json"
    resp = safe_request(url, timeout=15)
    if not resp:
        return None
    data = resp.json()
    _package_meta_cache[cache_key] = data
    return data


def resolve_latest_version(eco: str, name: str) -> Optional[str]:
    meta = fetch_package_metadata(eco, name)
    if not meta:
        return None
    if eco == 'npm':
        latest = meta.get('dist-tags', {}).get('latest')
        if latest:
            return latest
        versions = meta.get('versions', {})
        if versions:
            return list(versions.keys())[0]
    else:
        info = meta.get('info', {})
        if info.get('version'):
            return info['version']
        releases = meta.get('releases', {})
        if releases:
            return list(releases.keys())[0]
    return None


def resolve_version(eco: str, name: str, version_spec: str) -> Optional[str]:
    if version_spec and re.match(r'^[\w\d.+-~]+$', version_spec):
        return version_spec
    return resolve_latest_version(eco, name)


def load_namespaced_malicious_list(file_path: Path) -> Set[str]:
    malicious_set = set()
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                name = line.strip()
                if name and not name.startswith('#'):
                    if ':' not in name:
                        malicious_set.add(f"npm:{name}")
                        malicious_set.add(f"pypi:{name}")
                    else:
                        malicious_set.add(name)
    return malicious_set


def find_local_archive(local_dir: Optional[Path], eco: str, name: str, version: str) -> Optional[Path]:
    if not local_dir or not local_dir.exists():
        return None
    base_name = safe_filename(name)
    standard_names = [
        f"{name}-{version}.tgz", f"{name}-{version}.tar.gz",
        f"{name}-{version}.whl", f"{name}-{version}.zip"
    ]
    for fname in standard_names:
        p = local_dir / fname
        if p.exists():
            return p
    if name.startswith('@'):
        scoped_names = [
            f"{base_name}-{version}.tgz", f"{base_name}-{version}.tar.gz",
            f"{base_name}-{version}.whl", f"{base_name}-{version}.zip"
        ]
        for fname in scoped_names:
            p = local_dir / fname
            if p.exists():
                return p
    datadog_pattern = re.compile(rf'\d{{4}}-\d{{2}}-\d{{2}}-{re.escape(name)}-v{re.escape(version)}\.zip$')
    for p in local_dir.rglob('*.zip'):
        if datadog_pattern.search(p.name):
            return p
    if name.startswith('@'):
        datadog_pattern2 = re.compile(rf'\d{{4}}-\d{{2}}-\d{{2}}-{re.escape(base_name)}-v{re.escape(version)}\.zip$')
        for p in local_dir.rglob('*.zip'):
            if datadog_pattern2.search(p.name):
                return p
    for ext in ['*.tgz', '*.tar.gz', '*.whl', '*.zip']:
        for p in local_dir.rglob(ext):
            pname = p.name
            if name in pname and version in pname:
                return p
            if base_name in pname and version in pname:
                return p
    return None


# ================ DOWNLOAD FUNCTIONS ================
def download_npm(package_name: str, version: str, dest_dir: Path, local_dir: Optional[Path] = None) -> Tuple[Path, Dict]:
    local_path = find_local_archive(local_dir, 'npm', package_name, version) if local_dir else None
    if local_path and local_path.exists():
        print(f"  [LOCAL] Using local archive: {local_path}")
        dest_dir.mkdir(parents=True, exist_ok=True)
        archive_path = dest_dir / local_path.name
        archive_path.write_bytes(local_path.read_bytes())
        meta = fetch_package_metadata('npm', package_name)
        if not meta:
            # FIXED v4.9.6: Stub without "versions" key to trigger metadata_completeness=False
            meta = {"name": package_name}
        return archive_path, {"registry_metadata": meta, "version_metadata": meta.get('versions', {}).get(version, {}), "is_local": True}
    meta = fetch_package_metadata('npm', package_name)
    if not meta:
        raise RuntimeError(f"Failed to fetch npm metadata for {package_name} (not in registry and not found locally)")
    version_info = meta.get("versions", {}).get(version)
    if not version_info:
        raise ValueError(f"Version {version} not found for {package_name}")
    tarball_url = version_info["dist"]["tarball"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_name = safe_filename(package_name)
    archive_path = dest_dir / f"{safe_name}-{version}.tgz"
    file_resp = safe_request(tarball_url, timeout=60)
    if not file_resp:
        raise RuntimeError(f"Failed to download tarball for {package_name}")
    archive_path.write_bytes(file_resp.content)
    save_raw_json(meta, RAW_METADATA_DIR / "npm", f"{safe_name}_{version}.json")
    return archive_path, {"registry_metadata": meta, "version_metadata": version_info, "is_local": False}


def download_pypi(package_name: str, version: str, dest_dir: Path, local_dir: Optional[Path] = None) -> Tuple[Path, Dict]:
    local_path = find_local_archive(local_dir, 'pypi', package_name, version) if local_dir else None
    if local_path and local_path.exists():
        print(f"  [LOCAL] Using local archive: {local_path}")
        dest_dir.mkdir(parents=True, exist_ok=True)
        archive_path = dest_dir / local_path.name
        archive_path.write_bytes(local_path.read_bytes())
        meta = fetch_package_metadata('pypi', package_name, version)
        if not meta:
            meta = {"info": {}, "urls": []}
        return archive_path, {"registry_metadata": meta, "general_metadata": None, "downloaded_as": "local", "package_name": package_name, "is_local": True}
    version_meta = fetch_package_metadata('pypi', package_name, version)
    if not version_meta:
        raise RuntimeError(f"Failed to fetch PyPI metadata for {package_name}=={version} (not in registry and not found locally)")
    general_meta = fetch_package_metadata('pypi', package_name)
    if not general_meta:
        print(f"  [WARN] Failed to fetch general metadata for {package_name}, release history will be empty")
    urls = version_meta.get("urls", [])
    if not urls:
        raise ValueError(f"No downloadable files for {package_name}=={version}")
    chosen = next((u for u in urls if u["packagetype"] == "sdist"), urls[0])
    file_url = chosen["url"]
    filename = chosen["filename"]
    downloaded_as = chosen["packagetype"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    archive_path = dest_dir / filename
    file_resp = safe_request(file_url, timeout=60)
    if not file_resp:
        raise RuntimeError(f"Failed to download file for {package_name}")
    archive_path.write_bytes(file_resp.content)
    safe_name = safe_filename(package_name)
    save_raw_json(version_meta, RAW_METADATA_DIR / "pypi", f"{safe_name}_{version}.json")
    if general_meta:
        save_raw_json(general_meta, RAW_METADATA_DIR / "pypi", f"{safe_name}_general.json")
    return archive_path, {
        "registry_metadata": version_meta,
        "general_metadata": general_meta,
        "downloaded_as": downloaded_as,
        "package_name": package_name,
        "is_local": False
    }


# ================ SIGNAL 1: METADATA ================
def signal1_metadata(meta: Dict, ecosystem: str, package_name: str = '') -> Dict:
    registry_meta = meta.get('registry_metadata', {})
    npm_download_count = 0
    metadata_complete = True
    if ecosystem == 'pypi':
        info = registry_meta.get('info', {})
        if not info and meta.get('is_local', False):
            metadata_complete = False
        author_name = info.get('author')
        author_email = info.get('author_email')
        maintainers = info.get('maintainer') or info.get('maintainer_email')
        description = info.get('description', '')
        license_text = info.get('license')
        homepage = info.get('home_page', '')
        repo_url = info.get('project_urls', {}).get('Source', '') or info.get('home_page', '')
        keywords = info.get('keywords', '')
        latest_version = info.get('version')
        pkg_size_kb = 0
        urls = registry_meta.get('urls') or []
        for url_info in urls:
            if 'size' in url_info:
                pkg_size_kb = url_info['size'] // 1024
                break
        general_meta = meta.get('general_metadata')
        if general_meta:
            releases = general_meta.get('releases', {})
            version_count = len(releases)
            first_release = None
            last_release = None
            upload_times = []
            for ver, files in releases.items():
                for f in files:
                    if 'upload_time' in f:
                        upload_times.append(f['upload_time'])
            if upload_times:
                first_release = min(upload_times)
                last_release = max(upload_times)
        else:
            version_count = 1
            first_release = None
            last_release = None
            if urls and 'upload_time' in urls[0]:
                first_release = urls[0]['upload_time']
                last_release = first_release
    else:
        # FIXED v4.9.6: Stub without "versions" correctly triggers incomplete
        if meta.get('is_local', False) and not registry_meta.get('versions'):
            metadata_complete = False
        # URL encode for scoped packages
        try:
            encoded_pkg = urllib.parse.quote(package_name, safe='')
            dl_resp = safe_request(f"{NPM_DOWNLOADS_API}/last-month/{encoded_pkg}", timeout=10)
            if dl_resp:
                dl_data = dl_resp.json()
                npm_download_count = dl_data.get('downloads', 0)
        except:
            pass
        author_name = None
        author_email = None
        author_raw = registry_meta.get('author')
        if isinstance(author_raw, dict):
            author_name = author_raw.get('name')
            author_email = author_raw.get('email')
        elif isinstance(author_raw, str):
            author_name = author_raw
        maintainers = ', '.join([
            m.get('name', '') for m in registry_meta.get('maintainers', []) if m.get('name')
        ])
        description = registry_meta.get('description', '')
        license_raw = registry_meta.get('license', {})
        license_text = license_raw.get('type') if isinstance(license_raw, dict) else license_raw
        homepage = registry_meta.get('homepage', '')
        repo_url = registry_meta.get('repository', {}).get('url', '') if isinstance(
            registry_meta.get('repository'), dict) else registry_meta.get('repository', '')
        keywords = registry_meta.get('keywords', [])
        if isinstance(keywords, list):
            keywords = ', '.join(keywords[:10])
        version_count = len(registry_meta.get('versions', {}))
        latest_version = registry_meta.get('dist-tags', {}).get('latest')
        # size: get from the specific version's dist
        version_info = registry_meta.get('versions', {}).get(latest_version, {})
        pkg_size_kb = 0
        if 'dist' in version_info and 'unpackedSize' in version_info['dist']:
            pkg_size_kb = version_info['dist']['unpackedSize'] // 1024
        first_release = None
        last_release = None
        if 'time' in registry_meta:
            time_data = registry_meta['time']
            version_dates = [d for k, d in time_data.items() if k not in ['created', 'modified']]
            if version_dates:
                first_release = min(version_dates)
                last_release = max(version_dates)
    return {
        'author_name': author_name,
        'author_email': author_email,
        'maintainers': maintainers,
        'description': description[:500],
        'license': license_text,
        'homepage': homepage,
        'repository_url': repo_url[:200],
        'version_count': version_count,
        'latest_version': latest_version,
        'first_release_date': first_release,
        'last_release_date': last_release,
        'package_size_kb': pkg_size_kb,
        'keywords': keywords[:200] if keywords else '',
        'has_description': bool(description),
        'has_license': bool(license_text),
        'has_homepage': bool(homepage),
        'npm_download_count': npm_download_count,
        'metadata_completeness': metadata_complete
    }


# ================ SIGNAL 2: DEPENDENCY TREE ================
def get_raw_deps(eco: str, name: str, version_spec: str) -> Dict[str, str]:
    cache_key = (eco, name, version_spec)
    if cache_key in _deps_cache:
        return _deps_cache[cache_key]
    resolved_version = resolve_version(eco, name, version_spec)
    if not resolved_version:
        return {}
    deps = {}
    if eco == 'npm':
        meta = fetch_package_metadata('npm', name)
        if meta:
            ver_data = meta.get('versions', {}).get(resolved_version)
            if ver_data:
                deps = ver_data.get('dependencies', {})
    else:
        meta = fetch_package_metadata('pypi', name, resolved_version)
        if meta:
            info = meta.get('info', {})
            requires_dist = info.get('requires_dist', [])
            if requires_dist:
                for dep_str in requires_dist:
                    marker = dep_str.split(';')[1].strip() if ';' in dep_str else ''
                    if marker and 'extra' in marker.lower():
                        continue
                    base_dep = dep_str.split(';')[0].strip()
                    match = re.match(r'^([a-zA-Z0-9_.-]+)', base_dep)
                    if match:
                        dep_name = match.group(1)
                        deps[dep_name] = '*'
            if not deps:
                requires = info.get('requires', {})
                if isinstance(requires, dict):
                    deps = requires
    _deps_cache[cache_key] = deps
    return deps


def get_deps_recursive(eco: str, name: str, version_spec: str,
                       visited: Set[str], depth: int,
                       malicious_set: Set[str]) -> Tuple[Dict, int, bool, int]:
    if depth > MAX_DEPENDENCY_DEPTH or name in visited:
        return {}, 0, False, 0
    visited.add(name)
    deps = get_raw_deps(eco, name, version_spec)
    namespaced_name = f"{eco}:{name}"
    has_malicious = namespaced_name in malicious_set
    total_count = len(deps)
    max_rel_depth = 0
    for dep_name, dep_ver in deps.items():
        sub_deps, sub_count, sub_mal, sub_rel_depth = get_deps_recursive(
            eco, dep_name, dep_ver, visited, depth + 1, malicious_set
        )
        total_count += sub_count
        has_malicious = has_malicious or sub_mal
        max_rel_depth = max(max_rel_depth, sub_rel_depth + 1)
    return deps, total_count, has_malicious, max_rel_depth


def parse_deps_from_local(extracted_dir: Path, ecosystem: str) -> Dict[str, str]:
    deps = {}
    if ecosystem == 'npm':
        pkg_json = next(extracted_dir.rglob('package.json'), None)
        if pkg_json and pkg_json.exists():
            try:
                with open(pkg_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                deps = data.get('dependencies', {})
            except:
                pass
    else:
        patterns = ['METADATA', 'PKG-INFO']
        found = False
        for pattern in patterns:
            for f in extracted_dir.rglob(pattern):
                if f.is_file():
                    try:
                        text = f.read_text(encoding='utf-8', errors='ignore')
                        for line in text.split('\n'):
                            if line.startswith('Requires-Dist:'):
                                dep_str = line.replace('Requires-Dist:', '').strip()
                                marker = dep_str.split(';')[1].strip() if ';' in dep_str else ''
                                if marker and 'extra' in marker.lower():
                                    continue
                                base_dep = dep_str.split(';')[0].strip()
                                match = re.match(r'^([a-zA-Z0-9_.-]+)', base_dep)
                                if match:
                                    deps[match.group(1)] = '*'
                            elif line.startswith('Requires:'):
                                dep_str = line.replace('Requires:', '').strip()
                                if dep_str:
                                    for dep in dep_str.split(','):
                                        dep = dep.strip()
                                        if dep:
                                            match = re.match(r'^([a-zA-Z0-9_.-]+)', dep)
                                            if match:
                                                deps[match.group(1)] = '*'
                        if deps:
                            found = True
                            break
                    except:
                        pass
            if found:
                break
        if not deps:
            setup_py = next(extracted_dir.rglob('setup.py'), None)
            if setup_py and setup_py.exists():
                try:
                    text = setup_py.read_text(encoding='utf-8', errors='ignore')
                    match = re.search(r'install_requires\s*=\s*\[(.*?)\]', text, re.DOTALL)
                    if match:
                        deps_str = match.group(1)
                        for dep in re.findall(r"['\"]([^'\"]+)['\"]", deps_str):
                            dep_name = dep.split('>')[0].split('<')[0].split('=')[0].strip()
                            if dep_name:
                                deps[dep_name] = '*'
                except:
                    pass
    return deps


def signal2_dependency_tree(extracted_dir: Path, ecosystem: str,
                            pkg_name: str, pkg_version: str,
                            malicious_set: Set[str], meta: Dict) -> Dict:
    is_local = meta.get('is_local', False)
    direct_deps = {}
    if not is_local:
        if ecosystem == 'npm':
            reg_meta = fetch_package_metadata('npm', pkg_name)
            if reg_meta:
                ver_data = reg_meta.get('versions', {}).get(pkg_version)
                if ver_data:
                    direct_deps = ver_data.get('dependencies', {})
        else:
            reg_meta = fetch_package_metadata('pypi', pkg_name, pkg_version)
            if reg_meta:
                info = reg_meta.get('info', {})
                requires_dist = info.get('requires_dist', [])
                if requires_dist:
                    for dep_str in requires_dist:
                        marker = dep_str.split(';')[1].strip() if ';' in dep_str else ''
                        if marker and 'extra' in marker.lower():
                            continue
                        base_dep = dep_str.split(';')[0].strip()
                        match = re.match(r'^([a-zA-Z0-9_.-]+)', base_dep)
                        if match:
                            direct_deps[match.group(1)] = '*'
                if not direct_deps:
                    requires = info.get('requires', {})
                    if isinstance(requires, dict):
                        direct_deps = requires
    if not direct_deps:
        direct_deps = parse_deps_from_local(extracted_dir, ecosystem)
        if direct_deps:
            print(f"  [FALLBACK] Parsed {len(direct_deps)} deps from local files")
    visited = set()
    total_count = 0
    has_malicious = False
    max_total_depth = 0
    full_tree = {pkg_name: {'version': pkg_version, 'dependencies': {}}}
    for dep_name, dep_ver in direct_deps.items():
        if f"{ecosystem}:{dep_name}" in malicious_set:
            has_malicious = True
        sub_deps, sub_count, sub_mal, sub_rel_depth = get_deps_recursive(
            ecosystem, dep_name, dep_ver, visited, 1, malicious_set
        )
        total_count += sub_count
        has_malicious = has_malicious or sub_mal
        max_total_depth = max(max_total_depth, sub_rel_depth + 1)
        full_tree[pkg_name]['dependencies'][dep_name] = {
            'version': dep_ver,
            'dependencies': sub_deps
        }
    safe_name = safe_filename(pkg_name)
    tree_filename = f"{safe_name}_{pkg_version}_dep_tree.json"
    save_raw_json(full_tree, RAW_DEP_TREE_DIR / ecosystem, tree_filename)
    # NOTE (see file header note #4): total_dependency_count counts
    # TRANSITIVE dependencies only - it does NOT include the direct
    # dependencies themselves (those are direct_dependency_count).
    # For the full dependency graph size, use
    # direct_dependency_count + total_dependency_count.
    return {
        'direct_dependency_count': len(direct_deps),
        'total_dependency_count': total_count,
        'max_dependency_depth': max_total_depth,
        'has_malicious_dependency': has_malicious,
        'top_dependencies': ', '.join(list(direct_deps.keys())[:10])[:200],
        'dependency_tree_file': str(RAW_DEP_TREE_DIR / ecosystem / tree_filename)
    }


# ================ SIGNAL 3: MAINTAINER REPUTATION ================
def extract_github_owner_repo(url: str) -> Tuple[Optional[str], Optional[str]]:
    if not url or 'github.com' not in url:
        return None, None
    clean = url.replace('git+', '').replace('.git', '').replace('https://', '').replace('http://', '')
    match = re.match(r'github\.com/([^/]+)/([^/]+)', clean)
    if match:
        return match.group(1), match.group(2)
    match = re.match(r'([^\.]+)\.github\.(?:io|com)/([^/]+)', clean)
    if match:
        return match.group(1), match.group(2)
    return None, None


def signal3_maintainer_reputation(meta: Dict, ecosystem: str) -> Dict:
    registry_meta = meta.get('registry_metadata', {})
    repo_url = ''
    author_email = None
    if ecosystem == 'pypi':
        info = registry_meta.get('info', {})
        repo_url = info.get('project_urls', {}).get('Source', '') or info.get('home_page', '')
        author_email = info.get('author_email')
        if not author_email:
            author_email = info.get('maintainer_email')
    else:
        if isinstance(registry_meta.get('repository'), dict):
            repo_url = registry_meta['repository'].get('url', '')
        elif isinstance(registry_meta.get('repository'), str):
            repo_url = registry_meta['repository']
        if not repo_url and 'homepage' in registry_meta:
            repo_url = registry_meta['homepage']
        author_raw = registry_meta.get('author')
        if isinstance(author_raw, dict):
            author_email = author_raw.get('email')
        if not author_email and 'maintainers' in registry_meta:
            maintainers = registry_meta.get('maintainers', [])
            if maintainers and isinstance(maintainers[0], dict):
                author_email = maintainers[0].get('email')
    is_temp_email = is_disposable_email(author_email)
    owner, repo = extract_github_owner_repo(repo_url)
    stars, forks, issues, followers = 0, 0, 0, 0
    account_age_days = None
    contributors_count = 0
    token = os.environ.get('GITHUB_TOKEN')
    headers = {'Authorization': f'token {token}'} if token else {}
    if owner and repo:
        repo_resp = safe_request(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers, timeout=10)
        if repo_resp:
            repo_data = repo_resp.json()
            stars = repo_data.get('stargazers_count', 0)
            forks = repo_data.get('forks_count', 0)
            issues = repo_data.get('open_issues_count', 0)
            safe_name = safe_filename(owner)
            save_raw_json(repo_data, RAW_GITHUB_DIR, f"{safe_name}_{repo}_repo.json")
        user_resp = safe_request(f"{GITHUB_API}/users/{owner}", headers=headers, timeout=10)
        if user_resp:
            user_data = user_resp.json()
            followers = user_data.get('followers', 0)
            created_at = user_data.get('created_at')
            if created_at:
                created = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                account_age_days = (datetime.now().astimezone() - created).days
            safe_name = safe_filename(owner)
            save_raw_json(user_data, RAW_GITHUB_DIR, f"{safe_name}_profile.json")
        try:
            contrib_resp = safe_request(f"{GITHUB_API}/repos/{owner}/{repo}/contributors?per_page=1", headers=headers, timeout=10)
            if contrib_resp:
                link_header = contrib_resp.headers.get('Link', '')
                if 'rel="last"' in link_header:
                    match = re.search(r'page=(\d+)>; rel="last"', link_header)
                    if match:
                        contributors_count = int(match.group(1))
                    else:
                        contributors_count = len(contrib_resp.json()) if contrib_resp.json() else 0
                else:
                    contributors_count = len(contrib_resp.json()) if contrib_resp.json() else 0
        except:
            pass
    maintainer_pkg_count = 0
    maintainer_unchecked = False
    if ecosystem == 'npm':
        npm_maintainer_name = None
        maintainers_list = registry_meta.get('maintainers', [])
        if maintainers_list and isinstance(maintainers_list[0], dict):
            npm_maintainer_name = maintainers_list[0].get('name')
        if not npm_maintainer_name and 'author' in registry_meta:
            author = registry_meta.get('author')
            if isinstance(author, dict):
                npm_maintainer_name = author.get('name')
        if npm_maintainer_name:
            search_resp = safe_request(f"{NPM_REGISTRY}/-/v1/search?text=maintainer:{npm_maintainer_name}", timeout=10)
            if search_resp:
                data = search_resp.json()
                maintainer_pkg_count = data.get('total', 0)
            else:
                maintainer_unchecked = True
        else:
            maintainer_unchecked = True
    else:
        maintainer_unchecked = True
    return {
        'maintainer_email_domain_checked': bool(author_email),
        'is_disposable_email': is_temp_email,
        'github_repo_owner': owner,
        'repo_stars': stars,
        'repo_forks': forks,
        'repo_open_issues': issues,
        'maintainer_github_followers': followers,
        'maintainer_github_account_age_days': account_age_days,
        'maintainer_other_packages_count': maintainer_pkg_count,
        'maintainer_other_packages_unchecked': maintainer_unchecked,
        'has_github_repo': bool(owner and repo),
        'github_contributors_count': contributors_count
    }


# ================ SIGNAL 4: INSTALL SCRIPTS ================
class SetupVisitor(ast.NodeVisitor):
    def __init__(self):
        self.in_function = 0
        self.in_class = 0
        self.in_if_main = False
        self.in_setup_call = False
        self.dangerous_calls = []
        self.has_cmdclass = False

    def visit_FunctionDef(self, node):
        self.in_function += 1
        self.generic_visit(node)
        self.in_function -= 1

    def visit_AsyncFunctionDef(self, node):
        self.in_function += 1
        self.generic_visit(node)
        self.in_function -= 1

    def visit_ClassDef(self, node):
        self.in_class += 1
        self.generic_visit(node)
        self.in_class -= 1

    def visit_If(self, node):
        if isinstance(node.test, ast.Compare) and len(node.test.comparators) == 1:
            left = node.test.left
            right = node.test.comparators[0]
            if (isinstance(left, ast.Name) and left.id == '__name__' and
                isinstance(right, ast.Constant) and right.value == '__main__'):
                old_state = self.in_if_main
                self.in_if_main = True
                self.generic_visit(node)
                self.in_if_main = old_state
                return
        self.generic_visit(node)

    def visit_Call(self, node):
        is_setup = False
        if isinstance(node.func, ast.Name) and node.func.id == 'setup':
            is_setup = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr == 'setup':
            is_setup = True

        if is_setup:
            self.in_setup_call = True
            self.generic_visit(node)
            self.in_setup_call = False
            return

        if self.in_if_main:
            self.generic_visit(node)
            return

        if self.in_function > 0 or self.in_class > 0:
            self.generic_visit(node)
            return

        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == 'subprocess':
                func_name = f"subprocess.{node.func.attr}"
            elif node.func.value.id == 'os':
                func_name = f"os.{node.func.attr}"

        if func_name:
            dangerous_funcs = ['exec', 'eval', 'os.system', 'subprocess.Popen',
                              'subprocess.call', 'subprocess.check_output', 'subprocess.run']
            if any(danger in func_name for danger in dangerous_funcs):
                snippet = ast.unparse(node)[:200]
                self.dangerous_calls.append(f"[TOP-LEVEL-AST] {snippet}")

        self.generic_visit(node)

    def visit_keyword(self, node):
        if self.in_setup_call and node.arg == 'cmdclass' and isinstance(node.value, ast.Dict):
            self.has_cmdclass = True
        self.generic_visit(node)


def ast_extract_setup_danger(text: str) -> Tuple[str, bool]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return "", False
    visitor = SetupVisitor()
    visitor.visit(tree)
    script_parts = []
    has_script = False
    if visitor.dangerous_calls:
        script_parts.extend(visitor.dangerous_calls[:5])
        has_script = True
    if visitor.has_cmdclass:
        script_parts.append("[AST] cmdclass detected")
        has_script = True
    return '\n'.join(script_parts), has_script


def parse_setup_cfg(extracted_dir: Path) -> Tuple[str, bool]:
    setup_cfg = next(extracted_dir.rglob('setup.cfg'), None)
    if not setup_cfg or not setup_cfg.exists():
        return "", False
    try:
        config = configparser.ConfigParser()
        config.read(setup_cfg)
        if config.has_section('options'):
            cmdclass = config.get('options', 'cmdclass', fallback='')
            if cmdclass:
                return f"[setup.cfg] cmdclass={cmdclass}", True
        if config.has_section('build_ext'):
            return "[setup.cfg] has build_ext section", True
        if config.has_section('build_clib'):
            return "[setup.cfg] has build_clib section", True
    except Exception:
        pass
    return "", False


def extract_pypi_install_scripts_from_setup_py(text: str) -> Tuple[str, bool]:
    ast_result, ast_has = ast_extract_setup_danger(text)
    if ast_has:
        return ast_result, ast_has
    script_parts = []
    has_script = False
    match = re.search(r'cmdclass\s*=\s*\{([^}]*)\}', text, re.DOTALL)
    if match:
        cmdclass = match.group(1)
        if re.search(r'[a-zA-Z_]+:', cmdclass):
            script_parts.append(f"cmdclass={{{cmdclass}}}")
            has_script = True
    match = re.search(r"distutils\.commands\.([a-zA-Z_]+)", text)
    if match:
        script_parts.append(f"distutils.commands.{match.group(1)}")
        has_script = True
    for pat in ['os.system(', 'subprocess.', 'exec(', 'eval(', 'compile(']:
        if pat in text:
            if pat == 'compile(':
                if re.search(r'(?<!re\.)compile\(', text):
                    idx = text.find('compile(')
                    start = max(0, idx - 30)
                    end = min(len(text), idx + 120)
                    snippet = text[start:end].replace('\n', ' ')
                    script_parts.append(f"...{snippet}...")
                    has_script = True
            else:
                idx = text.find(pat)
                start = max(0, idx - 30)
                end = min(len(text), idx + 120)
                snippet = text[start:end].replace('\n', ' ')
                script_parts.append(f"...{snippet}...")
                has_script = True
            break
    return '\n'.join(script_parts), has_script


def extract_pypi_install_scripts_from_pyproject_toml(file_path: Path) -> Tuple[str, bool]:
    if not file_path.exists():
        return "", False
    text = file_path.read_text(encoding='utf-8', errors='ignore')
    script_parts = []
    has_script = False
    if tomllib:
        try:
            data = tomllib.loads(text)
            hatch_hooks = data.get('tool', {}).get('hatch', {}).get('build', {}).get('hooks', {})
            if hatch_hooks:
                script_parts.append(f"hatch_build_hooks={hatch_hooks}")
                has_script = True
            cmdclass = data.get('tool', {}).get('setuptools', {}).get('cmdclass', {})
            if cmdclass:
                script_parts.append(f"setuptools_cmdclass={cmdclass}")
                has_script = True
            poetry_build = data.get('tool', {}).get('poetry', {}).get('build')
            if poetry_build:
                script_parts.append(f"poetry_build_script={poetry_build}")
                has_script = True
            build_system = data.get('build-system', {})
            if build_system.get('build-backend'):
                backend = build_system.get('build-backend')
                if backend not in ['setuptools.build_meta', 'poetry.core.masonry.api', 'flit_core.buildapi']:
                    script_parts.append(f"custom_build_backend={backend}")
                    has_script = True
        except:
            pass
    if not has_script:
        hook_sections = ['[tool.hatch.build.hooks]', '[tool.setuptools.cmdclass]']
        if 'build = ' in text and '[tool.poetry]' in text:
            match = re.search(r'build\s*=\s*"([^"]+)"', text)
            if match:
                script_parts.append(f"poetry_build_script={match.group(1)}")
                has_script = True
        for section in hook_sections:
            if section in text:
                start = text.find(section)
                next_section = re.search(r'\n\[tool\.', text[start+1:])
                if next_section:
                    content = text[start:start+next_section.start()+1]
                else:
                    content = text[start:]
                script_parts.append(content[:500])
                has_script = True
                break
    return '\n'.join(script_parts), has_script


def signal4_install_scripts(extracted_dir: Path, ecosystem: str) -> Dict:
    install_script_text = ""
    has_script = False
    has_setup_py = False
    has_pyproject = False
    has_setup_cfg = False

    if ecosystem == 'npm':
        pkg_json = next(extracted_dir.rglob('package.json'), None)
        if pkg_json and pkg_json.exists():
            try:
                with open(pkg_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                scripts = data.get('scripts', {})
                install_parts = []
                for key in ['preinstall', 'install', 'postinstall', 'prepare']:
                    if key in scripts:
                        install_parts.append(scripts[key])
                if install_parts:
                    has_script = True
                    install_script_text = ' '.join(install_parts)
            except:
                install_script_text = ""
    else:
        setup_py = next(extracted_dir.rglob('setup.py'), None)
        if setup_py and setup_py.exists():
            has_setup_py = True
            try:
                text = setup_py.read_text(encoding='utf-8', errors='ignore')
                extracted_text, has_script = extract_pypi_install_scripts_from_setup_py(text)
                if extracted_text:
                    install_script_text = extracted_text
                    has_script = True
            except:
                install_script_text = ""
        cfg_text, cfg_has = parse_setup_cfg(extracted_dir)
        if cfg_has:
            has_setup_cfg = True
            if cfg_text:
                if install_script_text:
                    install_script_text += "\n" + cfg_text
                else:
                    install_script_text = cfg_text
                has_script = True
        pyproject = next(extracted_dir.rglob('pyproject.toml'), None)
        if pyproject and pyproject.exists():
            has_pyproject = True
            toml_text, toml_has_script = extract_pypi_install_scripts_from_pyproject_toml(pyproject)
            if toml_has_script:
                if install_script_text:
                    install_script_text += "\n" + toml_text
                else:
                    install_script_text = toml_text
                has_script = True

    if not has_script:
        install_script_text = ""

    lower_text = install_script_text.lower()
    flag_internet = any(kw in lower_text for kw in ['http', 'curl', 'wget', 'requests.get', 'fetch'])
    flag_system = any(kw in lower_text for kw in ['exec', 'eval', 'subprocess', 'os.system', 'system('])
    flag_download_run = any(kw in lower_text for kw in ['curl', 'wget', 'download', 'chmod', '/bin/'])

    flag_sensitive_read = False
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, lower_text):
            flag_sensitive_read = True
            break

    keyword_count = 0
    found_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_text:
            keyword_count += lower_text.count(kw)
            found_keywords.append(kw)

    script_lines = install_script_text.count('\n') + 1 if install_script_text else 0
    script_length = len(install_script_text)

    return {
        'has_install_script': has_script,
        'install_script_line_count': script_lines,
        'install_script_byte_length': script_length,
        'suspicious_keyword_count': keyword_count,
        'suspicious_keywords_found': ', '.join(list(set(found_keywords)))[:200],
        'flag_internet_call': flag_internet,
        'flag_system_command': flag_system,
        'flag_download_run': flag_download_run,
        'flag_sensitive_read': flag_sensitive_read,
        'install_script_preview': install_script_text[:200],
        'has_setup_py': has_setup_py,
        'has_pyproject_toml': has_pyproject,
        'has_setup_cfg': has_setup_cfg
    }


# ================ SIGNAL 5: STATIC CODE ANALYSIS ================
# CHANGED (see file header note #3): renamed from signal5_semantic_embedding.
# This function does AST-based risky-call counting and obfuscation flags -
# genuinely useful, but it is NOT a semantic embedding (no model, no vector,
# no notion of "meaning"). Real CodeBERT-based semantic similarity is a
# separate follow-up step - see extract_semantic_embeddings.py.
def signal5_code_analysis(extracted_dir: Path, pkg_name: str = '', pkg_version: str = '') -> Dict:
    py_extensions = {'.py'}
    js_extensions = {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'}
    source_extensions = py_extensions.union(js_extensions).union({'.sh'})
    other_text = {'.json', '.md', '.txt', '.yml', '.yaml', '.cfg', '.toml'}

    total_files = 0
    total_lines = 0
    extensions = set()
    obfuscation_flags = 0
    risky_func_counts = {}

    py_code = []
    js_code = []
    js_parse_success = True

    for file_path in extracted_dir.rglob('*'):
        if file_path.is_file():
            ext = file_path.suffix.lower()
            if ext:
                extensions.add(ext)

            is_source = ext in source_extensions
            if not (is_source or ext in other_text):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    content = ''.join(lines)

                    if is_source:
                        total_files += 1
                        total_lines += len(lines)

                    if ext in py_extensions:
                        py_code.append(content)
                    elif ext in js_extensions:
                        js_code.append(content)

                    if ext in source_extensions:
                        if 'base64' in content or 'b64decode' in content or 'eval(' in content:
                            obfuscation_flags += 1
            except:
                pass

    # Python AST
    for code in py_code:
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in RISKY_PY_FUNCS:
                            risky_func_counts[func_name] = risky_func_counts.get(func_name, 0) + 1
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        dotted = f"{node.func.value.id}.{node.func.attr}"
                        if dotted in RISKY_PY_FUNCS:
                            risky_func_counts[dotted] = risky_func_counts.get(dotted, 0) + 1
        except:
            pass

    # JavaScript
    for code in js_code:
        if HAS_ESPRIMA:
            try:
                tree = esprima.parseScript(code, {'range': False})
                tree_dict = tree.toDict()
                def walk(node):
                    if node is None:
                        return
                    if isinstance(node, (str, int, float, bool)):
                        return
                    if isinstance(node, list):
                        for item in node:
                            walk(item)
                        return
                    if isinstance(node, dict):
                        node_type = node.get('type')
                        if node_type == 'CallExpression':
                            callee = node.get('callee')
                            if callee:
                                if callee.get('type') == 'Identifier':
                                    name = callee.get('name')
                                    if name and name in RISKY_JS_FUNCS:
                                        risky_func_counts[name] = risky_func_counts.get(name, 0) + 1
                                elif callee.get('type') == 'MemberExpression':
                                    obj = callee.get('object', {})
                                    prop = callee.get('property', {})
                                    if obj.get('type') == 'Identifier' and prop.get('type') == 'Identifier':
                                        full = f"{obj.get('name')}.{prop.get('name')}"
                                        if full in RISKY_JS_FUNCS:
                                            risky_func_counts[full] = risky_func_counts.get(full, 0) + 1
                        for key, val in node.items():
                            walk(val)
                    elif hasattr(node, '__dict__'):
                        for key, val in vars(node).items():
                            walk(val)
                walk(tree_dict)
            except Exception as e:
                js_parse_success = False
                log_esprima_failure(pkg_name, pkg_version, str(file_path), str(e))
                for func in RISKY_JS_FUNCS:
                    count = len(re.findall(r'\b' + re.escape(func) + r'\b', code))
                    if count > 0:
                        risky_func_counts[func] = risky_func_counts.get(func, 0) + count
        else:
            for func in RISKY_JS_FUNCS:
                count = len(re.findall(r'\b' + re.escape(func) + r'\b', code))
                if count > 0:
                    risky_func_counts[func] = risky_func_counts.get(func, 0) + count

    feature_vector_str = json.dumps(risky_func_counts)
    ext_list = ', '.join(sorted(extensions))[:200]

    return {
        'source_file_count': total_files,
        'total_lines_of_code': total_lines,
        'file_extensions': ext_list,
        'risky_function_calls_total': sum(risky_func_counts.values()),
        'risky_function_calls_detail': feature_vector_str[:1000],
        'obfuscation_indicators': obfuscation_flags,
        'has_python_code': bool(py_code),
        'has_javascript_code': bool(js_code),
        'js_ast_parse_success': js_parse_success
    }


# ================ MAIN ================
def migrate_old_dataset():
    if not DATASET_CSV.exists():
        return
    with open(DATASET_CSV, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        try:
            existing_header = next(reader)
        except StopIteration:
            existing_header = []
    if existing_header != FIELD_NAMES:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = DATASET_CSV.parent / f"{DATASET_CSV.stem}_backup_{timestamp}{DATASET_CSV.suffix}"
        print(f"[SCHEMA] Header mismatch. Backing up to {backup_path}")
        DATASET_CSV.rename(backup_path)
        print("[SCHEMA] Starting fresh dataset.")


def append_to_dataset(row: dict):
    DATASET_CSV.parent.mkdir(parents=True, exist_ok=True)
    file_exists = DATASET_CSV.exists()
    extra_fields = set(row.keys()) - set(FIELD_NAMES)
    if extra_fields:
        print(f"  [WARN] Extra fields dropped: {', '.join(extra_fields)}")
    normalized_row = {field: row.get(field, None) for field in FIELD_NAMES}
    if file_exists:
        with open(DATASET_CSV, "a", newline="", encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=FIELD_NAMES)
            writer.writerow(normalized_row)
    else:
        with tempfile.NamedTemporaryFile(mode='w', newline='', encoding='utf-8',
                                         dir=DATASET_CSV.parent, delete=False) as f:
            writer = csv.DictWriter(f, fieldnames=FIELD_NAMES)
            writer.writeheader()
            writer.writerow(normalized_row)
            temp_path = Path(f.name)
        os.replace(temp_path, DATASET_CSV)


def process_package(ecosystem: str, package_name: str, version: str, label: str,
                    malicious_set: Set[str], local_archives_dir: Optional[Path]):
    start_time = time.time()
    print(f"\n[{ecosystem}] {package_name}=={version} ({label})")
    safe_name = safe_filename(package_name)
    dest_dir = QUARANTINE_ROOT / ecosystem / label / f"{safe_name}-{version}"

    try:
        if ecosystem == "npm":
            archive_path, meta = download_npm(package_name, version, dest_dir, local_archives_dir)
        elif ecosystem == "pypi":
            archive_path, meta = download_pypi(package_name, version, dest_dir, local_archives_dir)
        else:
            raise ValueError(f"Unknown ecosystem: {ecosystem}")
    except Exception as e:
        log_entry(ecosystem, package_name, version, label, 'ERROR', str(e), time.time() - start_time)
        print(f"  [ERROR] Failed to download: {e}")
        return

    file_hash = sha256_of_file(archive_path)
    print(f"  Downloaded -> {archive_path.name} (sha256: {file_hash[:16]}...)")

    extracted_dir = dest_dir / "extracted"
    extracted_success = safe_extract(archive_path, extracted_dir)
    if extracted_success:
        print(f"  Extracted -> {extracted_dir}")
    else:
        print(f"  [WARN] Extraction skipped (size > {MAX_ARCHIVE_SIZE_MB}MB)")

    data_source = 'local_archive' if meta.get('is_local', False) else 'live'

    signal1_result = signal1_metadata(meta, ecosystem, package_name)
    metadata_complete = signal1_result.get('metadata_completeness', True)
    training_eligible = metadata_complete

    row = {
        "package_name": package_name,
        "version": version,
        "ecosystem": ecosystem,
        "label": label,
        "sha256": file_hash,
        "data_source": data_source,
        "extraction_skipped": not extracted_success,
        "metadata_completeness": metadata_complete,
        "training_eligible": training_eligible
    }

    row.update(signal1_result)
    row.update(signal2_dependency_tree(extracted_dir, ecosystem, package_name, version, malicious_set, meta))
    row.update(signal3_maintainer_reputation(meta, ecosystem))
    row.update(signal4_install_scripts(extracted_dir, ecosystem))
    row.update(signal5_code_analysis(extracted_dir, package_name, version))

    append_to_dataset(row)
    duration = time.time() - start_time
    log_entry(ecosystem, package_name, version, label, 'SUCCESS', '', duration)
    print(f"  Row written to {DATASET_CSV} (took {duration:.1f}s)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", required=True,
                        help="CSV with columns: ecosystem,package_name,version,label")
    parser.add_argument("--malicious-list", help="Optional file with malicious package names (one per line, format: npm:name or pypi:name)")
    parser.add_argument("--local-archives", help="Optional directory containing local archive files (.tgz/.whl/.zip) for packages removed from registry")
    parser.add_argument("--limit", type=int, default=None,
                        help="Max NEW packages to process this run (e.g. 400). Already-"
                             "collected packages don't count against this, so re-running "
                             "the same command later advances to the next batch on its own.")
    args = parser.parse_args()

    ensure_dirs()
    init_log()
    migrate_old_dataset()

    local_dir = Path(args.local_archives) if args.local_archives else None
    if local_dir and not local_dir.exists():
        print(f"[WARN] Local archives directory '{local_dir}' not found, disabling.")
        local_dir = None

    malicious_set = set()
    if args.malicious_list and Path(args.malicious_list).exists():
        malicious_set = load_namespaced_malicious_list(Path(args.malicious_list))
        print(f"Loaded {len(malicious_set)} malicious package names")

    already_done = set()
    if DATASET_CSV.exists():
        with open(DATASET_CSV, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for r in reader:
                eco = r.get('ecosystem', '')
                name = r.get('package_name', '')
                ver = r.get('version', '')
                if eco and name and ver:
                    already_done.add((eco, name, ver))
        print(f"Found {len(already_done)} already collected packages.")

    print("\n📌 v5.0 Universal Edition:")
    print("   - --limit batching added for team-scale collection runs")
    print("   - Output now lands inside the repo (data/, quarantine/, raw/, logs/)")
    print("   - Signal 5 renamed to signal5_code_analysis (it's AST analysis, not embeddings)\n")

    new_count, skip_count, fail_count = 0, 0, 0
    with open(args.list, 'r', encoding='utf-8') as f:
        total_packages = sum(1 for _ in f) - 1
        f.seek(0)
        for idx, row in enumerate(csv.DictReader(f), 1):
            key = (row["ecosystem"], row["package_name"], row["version"])
            if key in already_done:
                skip_count += 1
                continue
            if args.limit is not None and new_count >= args.limit:
                print(f"\n[LIMIT] Reached --limit {args.limit} new packages. "
                      f"Stopping here - re-run the same command to continue with the next batch.")
                break
            try:
                process_package(
                    row["ecosystem"],
                    row["package_name"],
                    row["version"],
                    row["label"],
                    malicious_set,
                    local_dir
                )
                new_count += 1
            except Exception as e:
                print(f"  [ERROR] {row['package_name']}=={row['version']}: {e}")
                log_entry(row["ecosystem"], row["package_name"],
                          row["version"], row["label"], 'ERROR', str(e))
                fail_count += 1
                continue

    print(f"\n✅ Run complete. {new_count} new, {skip_count} already done, {fail_count} failed.")
    print(f"   Dataset: {DATASET_CSV}")
    print(f"   Log: {COLLECTION_LOG}")
    print(f"   Esprima parse failures: {ESPRIMA_PARSE_LOG}")
    print("\n📌 Modeling Ready:")
    print("   - `training_eligible` flag → filter or drop Signal 1/3 for ineligible rows.")
    print("   - This prevents metadata-completeness leakage.")

if __name__ == "__main__":
    main()