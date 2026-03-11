import base64
import io
import json
import os
import sys
import time
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import requests
import urllib3
import pandas as pd
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# ============================================
# CONFIGURATION
# ============================================

WORKDAY_CONFIG = {
    'client_id':     os.getenv('WORKDAY_CLIENT_ID'),
    'client_secret': os.getenv('WORKDAY_CLIENT_SECRET'),
    'token_url':     os.getenv('WORKDAY_TOKEN_URL'),
    'api_url':       os.getenv('WORKDAY_API_URL'),
    'scope':         os.getenv('WORKDAY_SCOPE'),
}

PROOFPOINT_CONFIG = {
    # Full URL to the phishing_extended endpoint e.g.:
    # https://results.us.securityeducation.com/api/reporting/v0.3.0/phishing_extended
    'base_url':                os.getenv('PROOFPOINT_BASE_URL'),
    'api_key':                 os.getenv('PROOFPOINT_API_KEY'),
    'page_size':               int(os.getenv('PROOFPOINT_PAGE_SIZE', '500')),
    'verify_ssl':              os.getenv('PROOFPOINT_VERIFY_SSL', 'False').lower() == 'true',
    'rate_limit_delay':        float(os.getenv('PROOFPOINT_RATE_LIMIT_DELAY', '1.0')),
    'retry_delay':             float(os.getenv('PROOFPOINT_RETRY_DELAY', '5.0')),
    'max_retries':             int(os.getenv('PROOFPOINT_MAX_RETRIES', '3')),
    'discovery_lookback_days': int(os.getenv('PROOFPOINT_DISCOVERY_LOOKBACK_DAYS', '14')),
    'discovery_max_pages':     int(os.getenv('PROOFPOINT_DISCOVERY_MAX_PAGES', '5')),
}

SHAREPOINT_CONFIG = {
    # Power Automate HTTP trigger URL.
    # file_type='excel' → ProofPoint_WorkDay_Splunk_Auto_Backup
    # file_type='csv'   → Autopipeline_MasterReports
    'webhook_url':  os.getenv('POWER_AUTOMATE_WEBHOOK_URL'),
    'webhook_auth': os.getenv('POWER_AUTOMATE_WEBHOOK_AUTH', ''),
}

# Splunk — all campaign-specific date windows are computed dynamically
# per campaign at runtime; these constants control query behaviour only.
SPLUNK_CONFIG = {
    'host':              os.getenv('SPLUNK_HOST', 'https://lilly-infosec.splunkcloud.com:8089'),
    'token':             os.getenv('SPLUNK_API_KEY'),
    'batch_size':        int(os.getenv('SPLUNK_BATCH_SIZE', '500')),
    'submit_delay':      float(os.getenv('SPLUNK_SUBMIT_DELAY', '3')),
    'max_retries':       int(os.getenv('SPLUNK_MAX_RETRIES', '5')),
    'retry_delay':       float(os.getenv('SPLUNK_RETRY_DELAY', '10')),
    'initial_poll':      float(os.getenv('SPLUNK_INITIAL_POLL', '5')),
    'retry_job_delay':   float(os.getenv('SPLUNK_RETRY_JOB_DELAY', '3')),
    # ±window around each user's anchor event when querying AzureAD
    'time_window_mins':  int(os.getenv('SPLUNK_TIME_WINDOW_MINUTES', '1440')),
}

STATE_FILE             = os.getenv('STATE_FILE_PATH', 'campaign_state.json')
START_DATE_OFFSET_DAYS = int(os.getenv('START_DATE_OFFSET_DAYS', '-2'))
END_DATE_OFFSET_DAYS   = int(os.getenv('END_DATE_OFFSET_DAYS',   '3'))

LOGGING_CONFIG = {
    'level':   os.getenv('LOG_LEVEL', 'INFO').upper(),
    'use_utc': os.getenv('LOG_USE_UTC', 'true').lower() == 'true',
}

WORKDAY_FIELDS = [
    'Level5SupervioryOrganizationid', 'Level5SupervioryOrganizationdesc',
    'Level6SupervioryOrganizationid', 'Level6SupervioryOrganizationdesc',
    'Level3SupervioryOrganizationid', 'Level3SupervioryOrganizationdesc',
    'Level4SupervioryOrganizationid', 'Level4SupervioryOrganizationdesc',
    'WorkdayEmployeeType', 'TerminationDate', 'ReHireDate', 'HireDate',
    'InternetEmailAddress', 'StatusCode', 'GlobalId', 'SystemLogonId',
    'StatusDescription', 'Title', 'WorkCountryDescription', 'SupervisorGlobalId',
    'OnboardDate', 'RetirementDate', 'SupervisorEmail', 'SupervisorSystemId',
    'JobSubFunctionCode', 'JobSubFunctionDescription',
]

PROOFPOINT_FIELDS = [
    'Email Address', 'First Name', 'Last Name', 'Campaign Guid', 'Users Guid',
    'Campaign Title', 'Phishing Template', 'Date Sent', 'Primary Email Opened',
    'Date Email Opened', 'Multi Email Open', 'Email Opened IP Address',
    'Email Opened Browser', 'Email Opened Browser Version', 'Email Opened OS',
    'Email Opened OS Version', 'Primary Clicked', 'Date Clicked', 'Multi Click Event',
    'Clicked IP Address', 'Clicked Browser', 'Clicked Browser Version',
    'Clicked OS', 'Clicked OS Version', 'Primary Compromised Login',
    'Date Login Compromised', 'Multi Compromised', 'Primary Attachment Open',
    'Date Attachment Open', 'Multi Attachment Open', 'Reported', 'Date Reported',
    'Passed?', 'Whois ISP', 'Whois Country', 'Teachable Moment Started',
    'Acknowledgement Completed', 'False Positive',
]

# ============================================
# LOGGING
# ============================================

def setup_logging() -> logging.Logger:
    logger = logging.getLogger('campaign_merge')
    logger.setLevel(getattr(logging, LOGGING_CONFIG['level'], logging.INFO))
    logger.propagate = False
    if logger.handlers:
        return logger
    formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    if LOGGING_CONFIG['use_utc']:
        formatter.converter = time.gmtime
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = setup_logging()

# ============================================
# STATE MANAGEMENT
# ============================================

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                state = json.load(f)
            logger.info("State loaded: %d processed, %d pending.",
                        len(state.get('processed_guids', [])),
                        len(state.get('pending_campaigns', [])))
            return state
        except Exception as e:
            logger.warning("Could not load state file — starting fresh. Reason: %s", e)
    return {'processed_guids': [], 'pending_campaigns': []}


def save_state(state: dict):
    state['last_run_utc'] = datetime.now(tz=timezone.utc).isoformat()
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, default=str)
    logger.info("State saved.")

# ============================================
# HELPERS
# ============================================

def _parse_date(raw: str):
    try:
        return datetime.fromisoformat(str(raw).replace('Z', '+00:00')).date()
    except Exception:
        raise ValueError(f"Cannot parse date: '{raw}'")


def _safe_filename(text: str) -> str:
    return ''.join(c if c.isalnum() or c in '-_ ' else '_' for c in str(text)).strip()


def parse_timestamp(ts):
    if not ts or pd.isna(ts):
        return None
    try:
        return pd.to_datetime(str(ts).replace('Z', '+00:00'))
    except Exception as e:
        logger.warning("Failed to parse timestamp '%s': %s", ts, e)
        return None


def is_false_positive(date_sent, date_clicked, whois_isp) -> bool:
    if not date_sent or not date_clicked or not whois_isp:
        return False
    sent    = parse_timestamp(date_sent)
    clicked = parse_timestamp(date_clicked)
    if not sent or not clicked:
        return False
    is_azure = 'microsoft azure' in str(whois_isp).lower()
    delta    = abs((clicked - sent).total_seconds())
    is_fp    = is_azure and delta <= 60
    if is_fp:
        logger.info("False positive: sent=%s clicked=%s delta=%.2fs isp=%s",
                    date_sent, date_clicked, delta, whois_isp)
    return is_fp


def add_executive_leadership_column(df: pd.DataFrame) -> pd.DataFrame:
    if 'JobSubFunctionCode' in df.columns:
        df['Executive Leadership'] = df['JobSubFunctionCode'].apply(
            lambda x: True if pd.notna(x) and str(x).strip() == 'JFA000011' else False
        )
        logger.info("Executives identified: %d", int(df['Executive Leadership'].sum()))
    else:
        df['Executive Leadership'] = False
        logger.warning("'JobSubFunctionCode' not found — Executive Leadership set to False.")
    return df

# ============================================
# SPLUNK OS ENRICHMENT
# ============================================

def _splunk_headers() -> dict:
    return {
        'Authorization': f"Splunk {SPLUNK_CONFIG['token']}",
        'Content-Type':  'application/x-www-form-urlencoded',
    }


def _splunk_parse_iso(ts):
    """Parse a Splunk timestamp string to a naive datetime."""
    if not ts or not str(ts).strip():
        return None
    ts = str(ts).strip().rstrip('Z')
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d',
                '%m/%d/%Y %H:%M:%S', '%m/%d/%Y'):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _splunk_time(dt) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%S')


def _normalize_os(os_val: str) -> str:
    """
    Normalise raw OS string to a canonical name using a priority-ordered map.
    First match wins.
    """
    if not os_val or not str(os_val).strip():
        return os_val or ''

    os_lower = str(os_val).strip().lower()

    OS_MAP = [
        ('ipados',    'iPadOS'),
        ('ios',       'iOS'),
        ('android',   'Android'),
        ('windows',   'Windows'),
        ('mac os',    'macOS'),
        ('macos',     'macOS'),
        ('darwin',    'macOS'),
        ('linux',     'Linux'),
        ('ubuntu',    'Linux'),
        ('debian',    'Linux'),
        ('fedora',    'Linux'),
        ('centos',    'Linux'),
        ('chrome os', 'ChromeOS'),
        ('chromeos',  'ChromeOS'),
        ('cros',      'ChromeOS'),
    ]
    for keyword, canonical in OS_MAP:
        if os_lower.startswith(keyword) or keyword in os_lower:
            return canonical

    return str(os_val).strip().title()


def _resolve_anchor(row_dict: dict):
    """
    Returns (timestamp_str, source) for the most relevant FAILURE event.

    Only users who actually FAILED (clicked, submitted data, opened
    attachment) or REPORTED are worth querying Splunk for OS data.

    Email-opened-only users and no-action users return ('', 'no_action')
    and are skipped entirely — they have no failure-event OS data in Splunk.
    """
    reported        = str(row_dict.get('Reported') or '').strip().upper()
    date_rep        = str(row_dict.get('Date Reported') or '').strip()
    date_clicked    = str(row_dict.get('Date Clicked') or '').strip()
    date_login      = str(row_dict.get('Date Login Compromised') or '').strip()
    date_attachment = str(row_dict.get('Date Attachment Open') or '').strip()

    if reported == 'TRUE' and date_rep:
        return date_rep, 'date_reported'
    elif date_clicked:
        return date_clicked, 'date_clicked'
    elif date_login:
        return date_login, 'date_login_compromised'
    elif date_attachment:
        return date_attachment, 'date_attachment_open'
    return '', 'no_action'


def _closest_match(candidates: list, anchor_dt):
    """Return the candidate closest in time to anchor_dt."""
    if not candidates:
        return None
    if anchor_dt is None:
        return max(candidates, key=lambda c: c['dt'])
    window = timedelta(minutes=SPLUNK_CONFIG['time_window_mins'])
    in_win = [c for c in candidates if abs(c['dt'] - anchor_dt) <= window]
    pool   = in_win if in_win else candidates
    return min(pool, key=lambda c: abs(c['dt'] - anchor_dt))


def _submit_job(query: str, earliest: str, latest: str) -> str:
    resp = requests.post(
        f"{SPLUNK_CONFIG['host']}/services/search/jobs",
        headers=_splunk_headers(),
        data={'search': query, 'output_mode': 'json',
              'earliest_time': earliest, 'latest_time': latest},
        verify=False, timeout=120,
    )
    resp.raise_for_status()
    return resp.json()['sid']


def _poll_and_fetch(sid: str) -> list:
    """
    Poll a Splunk search job until DONE then fetch results.
    Includes a hard timeout of 10 minutes per job to prevent hanging.
    Cancels the job if the timeout is exceeded.
    """
    url          = f"{SPLUNK_CONFIG['host']}/services/search/jobs/{sid}"
    job_timeout  = 600   # 10 minutes max per Splunk job
    elapsed      = 0
    poll_interval = 5

    time.sleep(SPLUNK_CONFIG['initial_poll'])
    elapsed += SPLUNK_CONFIG['initial_poll']

    while True:
        if elapsed >= job_timeout:
            logger.warning("Splunk job %s exceeded %ds timeout — cancelling.", sid, job_timeout)
            try:
                requests.delete(url, headers=_splunk_headers(), verify=False, timeout=10)
            except Exception:
                pass
            raise RuntimeError(f"Splunk job {sid} timed out after {job_timeout}s")

        resp  = requests.get(url, headers=_splunk_headers(),
                             params={'output_mode': 'json'}, verify=False, timeout=30)
        resp.raise_for_status()
        state = resp.json()['entry'][0]['content']['dispatchState']

        if state == 'DONE':
            break
        elif state == 'FAILED':
            raise RuntimeError(f"Splunk job {sid} FAILED")

        time.sleep(poll_interval)
        elapsed += poll_interval

    resp = requests.get(
        f"{SPLUNK_CONFIG['host']}/services/search/jobs/{sid}/results",
        headers=_splunk_headers(),
        params={'output_mode': 'json', 'count': 0},
        verify=False, timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get('results', [])


def _run_batches(batch_specs: list) -> dict:
    """Execute a list of (query, earliest, latest, label) specs and collect results."""
    raw   = defaultdict(list)
    total = len(batch_specs)
    for idx, (query, earliest, latest, label) in enumerate(batch_specs, 1):
        for attempt in range(1, SPLUNK_CONFIG['max_retries'] + 1):
            try:
                sid  = _submit_job(query, earliest, latest)
                rows = _poll_and_fetch(sid)
                for r in rows:
                    k = (r.get('userIdentity') or '').strip().lower()
                    if k:
                        raw[k].append(r)
                logger.info("Splunk %d/%d done — %d users accumulated.", idx, total, len(raw))
                time.sleep(SPLUNK_CONFIG['submit_delay'])
                break
            except Exception as exc:
                wait = SPLUNK_CONFIG['retry_delay'] * (2 ** (attempt - 1))
                logger.warning("%s attempt %d/%d: %s — retry in %.0fs",
                               label, attempt, SPLUNK_CONFIG['max_retries'], exc, wait)
                time.sleep(wait)
                if attempt == SPLUNK_CONFIG['max_retries']:
                    logger.error("%s failed after %d attempts — skipping.", label,
                                 SPLUNK_CONFIG['max_retries'])
    return dict(raw)


def _azuread_query(emails: list, earliest: str, latest: str):
    ef = ' OR '.join(f'"{e}"' for e in emails)
    el = ', '.join(f'"{e.lower()}"' for e in emails)
    q  = f"""
search index="lilly_infosec_azuread_diagnostics" category=SignInLogs resultSignature=SUCCESS ({ef})
| rename properties.userPrincipalName as userIdentity
| rename properties.deviceDetail.operatingSystem as splunk_os
| rename properties.deviceDetail.operatingSystemVersion as splunk_os_version
| where lower(userIdentity) IN ({el})
| where isnotnull(splunk_os) AND splunk_os != "" AND lower(splunk_os) != "null"
| eval ts = strftime(_time, "%Y-%m-%dT%H:%M:%S")
| sort 0 - _time
| table ts, userIdentity, callerIpAddress, splunk_os, splunk_os_version
""".strip()
    return q, earliest, latest


def _proofpoint_splunk_query(emails: list, campaign_earliest: str, campaign_latest: str):
    ef = ' OR '.join(f'"{e}"' for e in emails)
    el = ', '.join(f'"{e.lower()}"' for e in emails)
    q  = f"""
search index="lilly_infosec_proofpoint_education" ({ef})
| rename attributes.useremailaddress as userIdentity
| rename attributes.os               as pf_os
| rename attributes.os_version       as pf_os_version
| rename attributes.ip_address       as pf_ip
| rename attributes.eventtype        as eventtype
| where lower(userIdentity) IN ({el})
| where isnotnull(pf_os) AND pf_os != "" AND lower(pf_os) != "null"
| where eventtype IN ("Email Click","Data Submission","Attachment Open","Reported")
| eval ts = strftime(_time, "%Y-%m-%dT%H:%M:%S")
| sort 0 - _time
| table ts, userIdentity, pf_os, pf_os_version, pf_ip, eventtype
""".strip()
    # Scoped to campaign window so Splunk only scans the relevant partition
    return q, campaign_earliest, campaign_latest


def _parse_azuread(raw: dict) -> dict:
    out = {}
    for email, rows in raw.items():
        parsed = []
        for r in rows:
            dt     = _splunk_parse_iso(r.get('ts') or r.get('_time') or '')
            os_val = (r.get('splunk_os') or '').strip()
            if not dt or not os_val or os_val.lower() == 'null':
                continue
            parsed.append({
                'dt':         dt,
                'os':         _normalize_os(os_val),
                'os_version': r.get('splunk_os_version', ''),
                'ip':         r.get('callerIpAddress', ''),
                'ts':         r.get('ts') or r.get('_time') or '',
            })
        if parsed:
            out[email] = parsed
    return out


def _parse_proofpoint_splunk(raw: dict) -> dict:
    out = {}
    for email, rows in raw.items():
        parsed = []
        for r in rows:
            dt     = _splunk_parse_iso(r.get('ts') or r.get('_time') or '')
            os_val = (r.get('pf_os') or '').strip()
            if not dt or not os_val or os_val.lower() == 'null':
                continue
            parsed.append({
                'dt':         dt,
                'os':         _normalize_os(os_val),
                'os_version': r.get('pf_os_version', ''),
                'ip':         r.get('pf_ip', ''),
                'ts':         r.get('ts') or r.get('_time') or '',
                'eventtype':  r.get('eventtype', ''),
            })
        if parsed:
            out[email] = parsed
    return out


def _retry_single(unresolved_emails: list,
                  campaign_earliest: str,
                  campaign_latest: str) -> dict:
    """Phase 3: single-email AzureAD queries for still-unresolved users."""
    results = {}
    total   = len(unresolved_emails)
    logger.info("Phase 3: single-email retry for %d users...", total)
    for idx, email in enumerate(unresolved_emails, 1):
        q = f"""
search index="lilly_infosec_azuread_diagnostics" category=SignInLogs resultSignature=SUCCESS "{email}"
| rename properties.userPrincipalName as userIdentity
| rename properties.deviceDetail.operatingSystem as splunk_os
| rename properties.deviceDetail.operatingSystemVersion as splunk_os_version
| where lower(userIdentity) = lower("{email}")
| where isnotnull(splunk_os) AND splunk_os != "" AND lower(splunk_os) != "null"
| eval ts = strftime(_time, "%Y-%m-%dT%H:%M:%S")
| sort 0 - _time
| table ts, userIdentity, callerIpAddress, splunk_os, splunk_os_version
""".strip()
        try:
            sid  = _submit_job(q, campaign_earliest, campaign_latest)
            rows = _poll_and_fetch(sid)
            if rows:
                r      = rows[0]
                os_val = _normalize_os((r.get('splunk_os') or '').strip())
                if os_val and os_val.lower() != 'null':
                    results[email] = {
                        'os':         os_val,
                        'os_version': r.get('splunk_os_version', ''),
                        'ip':         r.get('callerIpAddress', ''),
                        'ts':         r.get('ts', ''),
                        'ts_source':  'retry→azuread',
                    }
                    logger.info("[%d/%d] %s ✓ %s", idx, total, email, os_val)
                else:
                    logger.info("[%d/%d] %s — no OS found", idx, total, email)
            else:
                logger.info("[%d/%d] %s — no results", idx, total, email)
        except Exception as exc:
            logger.warning("[%d/%d] %s WARN: %s", idx, total, email, exc)
        time.sleep(SPLUNK_CONFIG['retry_job_delay'])
    return results


def enrich_with_splunk_os(merged_df: pd.DataFrame,
                          campaign_earliest: str,
                          campaign_latest: str) -> pd.DataFrame:
    """
    Add Splunk OS columns to merged_df using a 3-phase lookup:
      Phase 1 — Proofpoint Splunk index  (fastest, most accurate)
      Phase 2 — AzureAD batch queries    (broader coverage)
      Phase 3 — single-email retry       (last resort for stragglers)

    campaign_earliest / campaign_latest define the Splunk search window
    and are derived from the campaign's fetch date range.
    No-action users (no clicked/opened/reported timestamps) are skipped.
    """
    logger.info("Starting Splunk OS enrichment for %d rows...", len(merged_df))

    rows = merged_df.to_dict('records')

    # Pre-compute anchors for every row
    for row in rows:
        ts_str, source    = _resolve_anchor(row)
        row['_ts_str']    = ts_str
        row['_ts_source'] = source
        row['_anchor_dt'] = _splunk_parse_iso(ts_str)

    active_emails = list(dict.fromkeys(
        str(row.get('Email Address') or '').strip().lower()
        for row in rows
        if str(row.get('Email Address') or '').strip()
        and row['_ts_source'] != 'no_action'
    ))

    skipped = len(rows) - len(active_emails)
    logger.info(
        "%d users will be queried in Splunk (failed/reported only) | "
        "%d skipped (no-action / email-opened-only — no failure OS data available).",
        len(active_emails), skipped,
    )

    if not active_emails:
        logger.info("No users need Splunk enrichment. Skipping all phases.")
        for col in ('splunk_lookup_timestamp', 'splunk_ts_source',
                    'splunk_os', 'splunk_os_version', 'splunk_ip', 'splunk_ts'):
            merged_df[col] = ''
        return merged_df

    # ── Phase 1: Proofpoint Splunk ────────────────────────────────────
    logger.info("Phase 1 — Proofpoint Splunk for %d users...", len(active_emails))
    pf_specs = []
    bs = SPLUNK_CONFIG['batch_size']
    for i in range(0, len(active_emails), bs):
        batch = active_emails[i:i + bs]
        q, e, l = _proofpoint_splunk_query(batch, campaign_earliest, campaign_latest)
        pf_specs.append((q, e, l, f"Proofpoint-{i}"))
    pf_raw     = _run_batches(pf_specs)
    proofpoint = _parse_proofpoint_splunk(pf_raw)
    logger.info("Phase 1 resolved %d users.", len(proofpoint))

    # ── Phase 2: AzureAD batch ────────────────────────────────────────
    missing = [e for e in active_emails if e not in proofpoint]
    logger.info("Phase 2 — AzureAD batch for %d users...", len(missing))

    email_windows = {}
    date_buckets  = defaultdict(list)
    for row in rows:
        email = str(row.get('Email Address') or '').strip().lower()
        if email not in missing:
            continue
        anchor = row['_anchor_dt']
        tw     = timedelta(minutes=SPLUNK_CONFIG['time_window_mins'])
        if anchor:
            e      = _splunk_time(anchor - tw)
            l      = _splunk_time(anchor + tw)
            bucket = anchor.strftime('%Y-%m-%d')
        else:
            e, l   = campaign_earliest, campaign_latest
            bucket = 'no_anchor'
        email_windows[email] = (e, l)
        date_buckets[bucket].append(email)

    for k in date_buckets:
        date_buckets[k] = list(dict.fromkeys(date_buckets[k]))

    az_specs = []
    for bucket, bemails in date_buckets.items():
        windows  = [email_windows[em] for em in bemails]
        earliest = min(w[0] for w in windows)
        latest   = max(w[1] for w in windows)
        for i in range(0, len(bemails), bs):
            batch = bemails[i:i + bs]
            q, e, l = _azuread_query(batch, earliest, latest)
            az_specs.append((q, e, l, f"AzureAD-{bucket}-{i}"))

    az_raw  = _run_batches(az_specs)
    azuread = _parse_azuread(az_raw)
    logger.info("Phase 2 resolved %d users.", len(azuread))

    # ── Phase 3: single-email retry ───────────────────────────────────
    still_missing = [e for e in active_emails if e not in proofpoint and e not in azuread]
    retry_results = _retry_single(still_missing, campaign_earliest, campaign_latest)
    logger.info("Phase 3 resolved %d users.", len(retry_results))

    # ── Assemble columns ──────────────────────────────────────────────
    for col in ('splunk_lookup_timestamp', 'splunk_ts_source',
                'splunk_os', 'splunk_os_version', 'splunk_ip', 'splunk_ts'):
        merged_df[col] = ''

    for i, row in enumerate(rows):
        email     = str(row.get('Email Address') or '').strip().lower()
        src       = row['_ts_source']
        anchor_dt = row['_anchor_dt']
        info      = {
            'splunk_os': '', 'splunk_os_version': '',
            'splunk_ip': '', 'splunk_ts': '', 'splunk_ts_source': '',
        }

        if src != 'no_action':
            pf_match = _closest_match(proofpoint.get(email, []), anchor_dt)
            if pf_match:
                info = {
                    'splunk_os':         pf_match['os'],
                    'splunk_os_version': pf_match['os_version'],
                    'splunk_ip':         pf_match['ip'],
                    'splunk_ts':         pf_match['ts'],
                    'splunk_ts_source':  f"proofpoint({pf_match['eventtype']})",
                }
            elif azuread.get(email):
                az_match = _closest_match(azuread[email], anchor_dt)
                if az_match:
                    info = {
                        'splunk_os':         az_match['os'],
                        'splunk_os_version': az_match['os_version'],
                        'splunk_ip':         az_match['ip'],
                        'splunk_ts':         az_match['ts'],
                        'splunk_ts_source':  src + '→azuread',
                    }
            elif email in retry_results:
                r = retry_results[email]
                info = {
                    'splunk_os':         r['os'],
                    'splunk_os_version': r['os_version'],
                    'splunk_ip':         r['ip'],
                    'splunk_ts':         r['ts'],
                    'splunk_ts_source':  r['ts_source'],
                }

        merged_df.at[i, 'splunk_lookup_timestamp'] = row['_ts_str']
        merged_df.at[i, 'splunk_ts_source']        = info['splunk_ts_source']
        merged_df.at[i, 'splunk_os']               = info['splunk_os']
        merged_df.at[i, 'splunk_os_version']       = info['splunk_os_version']
        merged_df.at[i, 'splunk_ip']               = info['splunk_ip']
        merged_df.at[i, 'splunk_ts']               = info['splunk_ts']

    resolved  = int((merged_df['splunk_os'] != '').sum())
    no_action = int((merged_df['splunk_ts_source'] == '').sum())
    logger.info("Splunk enrichment complete: resolved=%d no_action=%d unresolved=%d",
                resolved, no_action, len(merged_df) - resolved - no_action)
    return merged_df

# ============================================
# SHAREPOINT UPLOAD  (via Power Automate HTTP trigger)
# ============================================

def upload_to_sharepoint(file_bytes: bytes, filename: str, file_type: str):
    """
    Post a file to the Power Automate HTTP trigger.
      file_type='excel' → ProofPoint_WorkDay_Splunk_Auto_Backup
      file_type='csv'   → Autopipeline_MasterReports
    """
    webhook_url = SHAREPOINT_CONFIG['webhook_url']
    if not webhook_url:
        raise ValueError("POWER_AUTOMATE_WEBHOOK_URL is not set.")

    if file_type not in ('excel', 'csv'):
        raise ValueError(f"file_type must be 'excel' or 'csv', got: '{file_type}'")

    payload = {
        'filename':    filename,
        'file_type':   file_type,
        'file_base64': base64.b64encode(file_bytes).decode('utf-8'),
    }

    for attempt in range(1, PROOFPOINT_CONFIG['max_retries'] + 1):
        try:
            logger.info("Posting '%s' (type=%s) to Power Automate (attempt %d, %.1f KB)...",
                        filename, file_type, attempt, len(file_bytes) / 1024)

            headers = {'Content-Type': 'application/json'}
            if SHAREPOINT_CONFIG.get('webhook_auth'):
                headers['Authorization'] = SHAREPOINT_CONFIG['webhook_auth']

            resp = requests.post(webhook_url, json=payload, headers=headers, timeout=120)

            if resp.status_code in (200, 202):
                logger.info("Power Automate accepted '%s' → %s folder.",
                            filename, file_type.upper())
                return

            logger.warning("Unexpected HTTP %d from Power Automate (attempt %d): %s",
                           resp.status_code, attempt, resp.text[:300])

        except requests.RequestException as e:
            logger.error("Request error posting to Power Automate (attempt %d/%d): %s",
                         attempt, PROOFPOINT_CONFIG['max_retries'], e)

        if attempt < PROOFPOINT_CONFIG['max_retries']:
            wait = PROOFPOINT_CONFIG['retry_delay'] * attempt
            logger.info("Retrying in %.0fs...", wait)
            time.sleep(wait)

    raise RuntimeError(
        f"Failed to upload '{filename}' via Power Automate after "
        f"{PROOFPOINT_CONFIG['max_retries']} attempts."
    )

# ============================================
# CAMPAIGN DISCOVERY
# ============================================

def discover_campaigns_from_phishing_extended() -> list:
    """
    Discover unique campaigns without fetching all event rows.
    Uses includenoaction=FALSE to reduce volume, stops early when a full
    page returns zero new guids, and hard-caps at discovery_max_pages.
    """
    lookback_days = PROOFPOINT_CONFIG['discovery_lookback_days']
    max_pages     = PROOFPOINT_CONFIG['discovery_max_pages']
    today         = datetime.now(tz=timezone.utc).date()
    scan_start    = (today - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
    scan_end      = today.strftime('%Y-%m-%d')

    logger.info("Discovering campaigns (lookback %d days: %s → %s, max %d page(s))...",
                lookback_days, scan_start, scan_end, max_pages)

    headers    = {'x-apikey-token': PROOFPOINT_CONFIG['api_key']}
    page       = 1
    seen_guids = {}

    while page <= max_pages:
        params = {
            'page[number]':                     page,
            'page[size]':                       PROOFPOINT_CONFIG['page_size'],
            'filter[_campaignstartdate_start]': scan_start,
            'filter[_campaignstartdate_end]':   scan_end,
            'filter[_includenoaction]':         'FALSE',
        }

        for attempt in range(1, PROOFPOINT_CONFIG['max_retries'] + 1):
            try:
                if page > 1 or attempt > 1:
                    time.sleep(PROOFPOINT_CONFIG['rate_limit_delay'])

                resp = requests.get(PROOFPOINT_CONFIG['base_url'], headers=headers,
                                    params=params, timeout=30,
                                    verify=PROOFPOINT_CONFIG['verify_ssl'])

                if resp.status_code == 429:
                    wait = int(resp.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay']))
                    logger.warning("429 Too Many Requests. Sleeping %ds.", wait)
                    time.sleep(wait)
                    continue

                resp.raise_for_status()
                data      = resp.json()
                page_data = data.get('data', [])

                if not page_data:
                    logger.info("Discovery: no more records on page %d. Stopping.", page)
                    page = max_pages + 1
                    break

                new_on_page = 0
                for record in page_data:
                    attrs = record.get('attributes', {})
                    guid  = attrs.get('campaign_guid')
                    if not guid or guid in seen_guids:
                        continue
                    raw_start = attrs.get('campaignstartdate', '')
                    raw_end   = attrs.get('campaignenddate', raw_start)
                    try:
                        start_str = _parse_date(raw_start).strftime('%Y-%m-%d')
                    except ValueError:
                        start_str = ''
                    try:
                        end_str = _parse_date(raw_end).strftime('%Y-%m-%d')
                    except ValueError:
                        end_str = start_str
                    seen_guids[guid] = {
                        'guid':      guid,
                        'title':     attrs.get('campaignname') or guid,
                        'startDate': start_str,
                        'endDate':   end_str,
                    }
                    new_on_page += 1

                logger.info("Discovery page %d: %d record(s), %d new guid(s) (total: %d).",
                            page, len(page_data), new_on_page, len(seen_guids))

                if new_on_page == 0:
                    logger.info("No new campaigns on page %d — stopping early.", page)
                    page = max_pages + 1
                    break

                page += 1
                break

            except requests.RequestException as e:
                logger.error("Discovery error (attempt %d/%d): %s",
                             attempt, PROOFPOINT_CONFIG['max_retries'], e)
                if attempt == PROOFPOINT_CONFIG['max_retries']:
                    return list(seen_guids.values())
                time.sleep(PROOFPOINT_CONFIG['retry_delay'])
        else:
            break

    campaigns = list(seen_guids.values())
    logger.info("Discovery complete: %d unique campaign(s).", len(campaigns))
    for c in campaigns:
        logger.info("  guid=%-12s start=%-12s end=%-12s title='%s'",
                    c['guid'], c['startDate'], c['endDate'], c['title'])
    return campaigns


def sync_pending_campaigns(state: dict) -> dict:
    campaigns = discover_campaigns_from_phishing_extended()
    if not campaigns:
        logger.warning("No campaigns discovered — skipping sync.")
        return state

    processed   = set(state.get('processed_guids', []))
    pending_ids = {c['guid'] for c in state.get('pending_campaigns', [])}
    newly_queued = 0

    for c in campaigns:
        guid = c['guid']
        if guid in processed or guid in pending_ids:
            continue
        state['pending_campaigns'].append({
            'guid':         guid,
            'title':        c['title'],
            'startDate':    c['startDate'],
            'endDate':      c['endDate'],
            'detected_utc': datetime.now(tz=timezone.utc).isoformat(),
        })
        pending_ids.add(guid)
        newly_queued += 1
        logger.info("Queued new campaign: guid=%s title='%s'", guid, c['title'])

    logger.info("Sync complete: %d new | %d total pending | %d total processed.",
                newly_queued, len(state['pending_campaigns']), len(processed))
    return state


def get_reportable_campaigns(state: dict) -> list:
    today = datetime.now(tz=timezone.utc).date()
    ready, waiting = [], []
    for c in state.get('pending_campaigns', []):
        try:
            end_date   = _parse_date(c.get('endDate') or c.get('startDate', ''))
            ready_date = end_date + timedelta(days=END_DATE_OFFSET_DAYS)
        except ValueError as e:
            logger.warning("Skipping guid=%s — bad date: %s", c.get('guid'), e)
            continue
        if today >= ready_date:
            logger.info("READY   guid=%s endDate=%s readyDate=%s today=%s",
                        c['guid'], end_date, ready_date, today)
            ready.append(c)
        else:
            logger.info("WAITING guid=%s endDate=%s readyDate=%s today=%s (%d day(s) remaining)",
                        c['guid'], end_date, ready_date, today, (ready_date - today).days)
            waiting.append(c)
    logger.info("%d ready | %d waiting.", len(ready), len(waiting))
    return ready


def compute_date_range(campaign: dict) -> tuple:
    campaign_start = _parse_date(campaign['startDate'])
    campaign_end   = _parse_date(campaign.get('endDate') or campaign['startDate'])
    fetch_start    = (campaign_start + timedelta(days=START_DATE_OFFSET_DAYS)).strftime('%Y-%m-%d')
    fetch_end      = (campaign_end   + timedelta(days=END_DATE_OFFSET_DAYS)).strftime('%Y-%m-%d')
    logger.info("Campaign window: %s → %s | Fetch window: %s → %s",
                campaign_start, campaign_end, fetch_start, fetch_end)
    return fetch_start, fetch_end

# ============================================
# WORKDAY API
# ============================================

def get_workday_access_token() -> str:
    logger.info("Requesting Workday access token...")
    resp = requests.post(
        WORKDAY_CONFIG['token_url'],
        data={'grant_type': 'client_credentials', 'client_id': WORKDAY_CONFIG['client_id'],
              'client_secret': WORKDAY_CONFIG['client_secret'], 'scope': WORKDAY_CONFIG['scope']},
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    resp.raise_for_status()
    logger.info("Workday token acquired.")
    return resp.json()['access_token']


def fetch_workday_workers(campaign_start_date: str) -> list:
    logger.info("Fetching Workday workers (active OR terminated >= %s)...", campaign_start_date)
    token   = get_workday_access_token()
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    all_records, skip, page_size = [], 0, 1000
    select_fields = ','.join(WORKDAY_FIELDS)
    while True:
        filter_q = (
            f"$filter=InternetEmailAddress ne null and "
            f"(StatusDescription eq 'Active' or "
            f"(TerminationDate ne null and TerminationDate ge '{campaign_start_date}'))"
        )
        url = (f"{WORKDAY_CONFIG['api_url']}?{filter_q}"
               f"&$select={select_fields}&$top={page_size}&$skip={skip}")
        try:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            records = resp.json().get('value', [])
            if not records:
                break
            all_records.extend(records)
            logger.info("Workday page: +%d (total: %d)", len(records), len(all_records))
            skip += page_size
        except requests.RequestException as e:
            logger.error("Workday fetch error: %s", e)
            break
    logger.info("Total Workday records: %d", len(all_records))
    return all_records

# ============================================
# PROOFPOINT API
# ============================================

def fetch_proofpoint_records(start_date: str, end_date: str) -> list:
    logger.info("Fetching Proofpoint records (%s → %s)...", start_date, end_date)
    all_records, page_number = [], 1
    has_more_pages, expected_total = True, None
    headers = {'x-apikey-token': PROOFPOINT_CONFIG['api_key']}

    while has_more_pages:
        params = {
            'page[number]':                     page_number,
            'page[size]':                       PROOFPOINT_CONFIG['page_size'],
            'filter[_campaignstartdate_start]': start_date,
            'filter[_campaignstartdate_end]':   end_date,
            'filter[_includenoaction]':         'TRUE',
            'filter[_includedeletedusers]':     'TRUE',
        }
        for attempt in range(1, PROOFPOINT_CONFIG['max_retries'] + 1):
            try:
                if page_number > 1 or attempt > 1:
                    time.sleep(PROOFPOINT_CONFIG['rate_limit_delay'])
                resp = requests.get(PROOFPOINT_CONFIG['base_url'], headers=headers,
                                    params=params, timeout=30,
                                    verify=PROOFPOINT_CONFIG['verify_ssl'])
                if resp.status_code == 429:
                    wait = int(resp.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay']))
                    logger.warning("429 Too Many Requests. Sleeping %ds (attempt %d).", wait, attempt)
                    time.sleep(wait)
                    continue
                if resp.status_code == 504:
                    wait = PROOFPOINT_CONFIG['retry_delay'] * attempt
                    logger.warning("504 Gateway Timeout. Sleeping %.0fs (attempt %d).", wait, attempt)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                if expected_total is None:
                    expected_total = data.get('meta', {}).get('count')
                    if expected_total:
                        logger.info("Proofpoint total records: %s", expected_total)
                page_data = data.get('data', [])
                if page_data:
                    all_records.extend(page_data)
                    logger.info("Proofpoint page %d: +%d (total: %d)",
                                page_number, len(page_data), len(all_records))
                    page_number += 1
                else:
                    has_more_pages = False
                break
            except requests.RequestException as e:
                logger.error("Proofpoint error (attempt %d/%d): %s",
                             attempt, PROOFPOINT_CONFIG['max_retries'], e)
                if attempt == PROOFPOINT_CONFIG['max_retries']:
                    has_more_pages = False
                else:
                    time.sleep(PROOFPOINT_CONFIG['retry_delay'])

    logger.info("Total Proofpoint records: %d", len(all_records))
    if expected_total and len(all_records) < int(expected_total):
        logger.warning("Partial fetch: expected %s, got %d.", expected_total, len(all_records))
    return all_records

# ============================================
# PROOFPOINT TRANSFORM  (with all bug fixes)
# ============================================

def transform_proofpoint_data(records: list) -> list:
    """
    Bug fixes included vs original script:
      1. False positive also clears failure_condition (not just primary_clicked)
         so Passed? is correctly TRUE for false-positive clicks.
      2. Hardened campaigntype matching — strips whitespace, lowercases,
         handles 'data entry' as alias for 'data entry campaign'.
      3. Whois fields only populated from failure events (click/submission/
         attachment) — not from email views, matching Proofpoint UI behaviour.
      4. Unknown campaigntype falls back to: failed if ANY failure event exists.
    """
    logger.info("Transforming Proofpoint data...")
    grouped = defaultdict(list)
    for r in records:
        a = r['attributes']
        grouped[f"{a['user_guid']}_{a['campaign_guid']}"].append(r)

    transformed, fp_count = [], 0

    for _, events in grouped.items():
        events = sorted(events, key=lambda x: x['attributes']['eventtimestamp'])
        first  = events[0]['attributes']

        def by_type(t):
            return [e for e in events if e['attributes']['eventtype'] == t]

        views       = by_type('Email View')
        clicks      = by_type('Email Click')
        submissions = by_type('Data Submission')
        attachments = by_type('Attachment Open')
        tm_sent     = by_type('TM Sent')
        tm_done     = by_type('TM Complete')
        reported    = by_type('Reported')

        # ── Bug fix 2: hardened campaigntype matching ─────────────────
        campaign_type_raw = (
            events[0].get('campaigntype')
            or first.get('campaigntype', '')
            or ''
        )
        campaign_type = campaign_type_raw.strip().lower()

        logger.debug("campaigntype raw=%r normalised=%r user=%s campaign=%s",
                     campaign_type_raw, campaign_type,
                     first.get('useremailaddress'), first.get('campaignname'))

        if campaign_type == 'drive by':
            failed = bool(clicks)
        elif campaign_type in ('data entry campaign', 'data entry'):
            failed = bool(submissions)
        elif campaign_type == 'attachment':
            failed = bool(attachments)
        else:
            # ── Bug fix 4: safe fallback for unknown types ─────────────
            failed = bool(clicks) or bool(submissions) or bool(attachments)
            if campaign_type:
                logger.warning(
                    "Unrecognised campaigntype=%r for campaign=%r — "
                    "fallback logic applied (clicks=%d submissions=%d attachments=%d).",
                    campaign_type_raw, first.get('campaignname'),
                    len(clicks), len(submissions), len(attachments))
            else:
                logger.warning("campaigntype missing for user=%s campaign=%r — fallback applied.",
                               first.get('useremailaddress'), first.get('campaignname'))

        # ── Bug fix 3: Whois only from failure events ─────────────────
        if clicks:
            whois_src = clicks[0]['attributes']
        elif submissions:
            whois_src = submissions[0]['attributes']
        elif attachments:
            whois_src = attachments[0]['attributes']
        else:
            whois_src = {}   # no failure event — intentionally blank

        def first_attr(lst, key):
            return lst[0]['attributes'].get(key) if lst else None

        def b(cond):
            return 'TRUE' if cond else 'FALSE'

        date_sent       = first.get('senttimestamp')
        date_clicked    = first_attr(clicks, 'eventtimestamp')
        whois_isp       = whois_src.get('whois_isp')
        primary_clicked = bool(clicks)

        is_fp = is_false_positive(date_sent, date_clicked, whois_isp)
        if is_fp:
            primary_clicked = False
            failed          = False   # Bug fix 1: clear failure for FP
            fp_count += 1

        transformed.append({
            'Email Address':                first.get('useremailaddress'),
            'First Name':                   first.get('userfirstname'),
            'Last Name':                    first.get('userlastname'),
            'Campaign Guid':                first.get('campaign_guid'),
            'Users Guid':                   first.get('user_guid'),
            'Campaign Title':               first.get('campaignname'),
            'Phishing Template':            first.get('templatename'),
            'Date Sent':                    date_sent,
            'Primary Email Opened':         b(views),
            'Date Email Opened':            first_attr(views, 'eventtimestamp'),
            'Multi Email Open':             max(0, len(views) - 1),
            'Email Opened IP Address':      first_attr(views, 'ip_address'),
            'Email Opened Browser':         first_attr(views, 'browser'),
            'Email Opened Browser Version': first_attr(views, 'browser_version'),
            'Email Opened OS':              first_attr(views, 'os'),
            'Email Opened OS Version':      first_attr(views, 'os_version'),
            'Primary Clicked':              b(primary_clicked),
            'Date Clicked':                 date_clicked,
            'Multi Click Event':            max(0, len(clicks) - 1),
            'Clicked IP Address':           first_attr(clicks, 'ip_address'),
            'Clicked Browser':              first_attr(clicks, 'browser'),
            'Clicked Browser Version':      first_attr(clicks, 'browser_version'),
            'Clicked OS':                   first_attr(clicks, 'os'),
            'Clicked OS Version':           first_attr(clicks, 'os_version'),
            'Primary Compromised Login':    b(submissions),
            'Date Login Compromised':       first_attr(submissions, 'eventtimestamp'),
            'Multi Compromised':            max(0, len(submissions) - 1),
            'Primary Attachment Open':      b(attachments),
            'Date Attachment Open':         first_attr(attachments, 'eventtimestamp'),
            'Multi Attachment Open':        max(0, len(attachments) - 1),
            'Reported':                     b(reported),
            'Date Reported':                first_attr(reported, 'eventtimestamp'),
            'Passed?':                      b(not failed),
            'Whois ISP':                    whois_src.get('whois_isp'),
            'Whois Country':                whois_src.get('whois_country'),
            'Teachable Moment Started':     b(tm_sent),
            'Acknowledgement Completed':    b(tm_done),
            'False Positive':               b(is_fp),
        })

    logger.info("Transform complete: %d records (%d false positives).", len(transformed), fp_count)
    return transformed

# ============================================
# MERGE
# ============================================

def merge_datasets(proofpoint_df: pd.DataFrame, workday_df: pd.DataFrame) -> pd.DataFrame:
    logger.info("Merging Proofpoint and Workday datasets...")
    pp = proofpoint_df[PROOFPOINT_FIELDS].copy()
    wd = workday_df[WORKDAY_FIELDS + ['Executive Leadership']].copy()
    pp['Email Address']        = pp['Email Address'].str.lower().str.strip()
    wd['InternetEmailAddress'] = wd['InternetEmailAddress'].str.lower().str.strip()
    merged = pd.merge(pp, wd, left_on='Email Address', right_on='InternetEmailAddress',
                      how='left', suffixes=('_Proofpoint', '_Workday'))
    merged.drop(columns=['InternetEmailAddress'], errors='ignore', inplace=True)
    matched   = int(merged['GlobalId'].notna().sum())
    unmatched = int(merged['GlobalId'].isna().sum())
    logger.info("Merge complete: %d rows | matched=%d | unmatched=%d",
                len(merged), matched, unmatched)
    return merged

# ============================================
# FILE BUILDERS
# ============================================

def build_excel_bytes(workday_df: pd.DataFrame,
                      proofpoint_df: pd.DataFrame,
                      merged_df: pd.DataFrame) -> bytes:
    """
    3-sheet workbook → ProofPoint_WorkDay_Splunk_Auto_Backup.
    Merged Data sheet includes Splunk OS enrichment columns.
    """
    logger.info("Building Excel workbook in memory...")
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine='openpyxl') as writer:
        for sheet_name, df in [
            ('Workday Feed',    workday_df),
            ('Proofpoint Data', proofpoint_df),
            ('Merged Data',     merged_df),
        ]:
            df.to_excel(writer, sheet_name=sheet_name, index=False)
            ws = writer.sheets[sheet_name]
            for col in ws.columns:
                max_len = max((len(str(c.value or '')) for c in col), default=0)
                ws.column_dimensions[col[0].column_letter].width = min(max_len + 2, 50)
            ws.freeze_panes = 'A2'
            logger.info("  Sheet '%s': %d rows.", sheet_name, len(df))
    return buf.getvalue()


def build_csv_bytes(merged_df: pd.DataFrame) -> bytes:
    """Flat CSV of Merged Data (with Splunk columns) → Autopipeline_MasterReports."""
    return merged_df.to_csv(index=False, encoding='utf-8').encode('utf-8')

# ============================================
# PER-CAMPAIGN REPORT
# ============================================

def run_report_for_campaign(campaign: dict, workday_df: pd.DataFrame) -> bool:
    """
    Full pipeline for one campaign:
      1. Compute date window
      2. Fetch + transform Proofpoint (with bug fixes)
      3. Filter to this guid only
      4. Merge with Workday
      5. Enrich with Splunk OS (3-phase lookup)
      6. Build Excel (3 sheets incl. Splunk cols) + CSV (merged flat)
      7. Upload both via Power Automate to separate SharePoint folders
    """
    guid  = campaign['guid']
    title = campaign['title']

    logger.info("=" * 60)
    logger.info("Processing campaign: '%s'  guid=%s", title, guid)
    logger.info("=" * 60)

    # ── 1. Date window ────────────────────────────────────────────────
    fetch_start, fetch_end = compute_date_range(campaign)

    # Splunk uses the same window (ISO datetime strings)
    splunk_earliest = f"{fetch_start}T00:00:00"
    splunk_latest   = f"{fetch_end}T23:59:59"

    # ── 2. Fetch + transform Proofpoint ──────────────────────────────
    pp_records = fetch_proofpoint_records(fetch_start, fetch_end)
    if not pp_records:
        logger.error("No Proofpoint records for campaign %s. Skipping.", guid)
        return False

    all_proofpoint_df = pd.DataFrame(transform_proofpoint_data(pp_records))

    # ── 3. Filter to this campaign guid ──────────────────────────────
    proofpoint_df = all_proofpoint_df[
        all_proofpoint_df['Campaign Guid'] == guid
    ].copy()

    if proofpoint_df.empty:
        logger.warning("No records match guid=%s after filtering. Skipping.", guid)
        return False

    logger.info("Records for this campaign: %d (of %d in date window).",
                len(proofpoint_df), len(all_proofpoint_df))

    # ── 4. Merge with Workday ─────────────────────────────────────────
    merged_df = merge_datasets(proofpoint_df, workday_df)
    merged_df = merged_df[merged_df['Campaign Guid'] == guid].copy().reset_index(drop=True)

    # ── 5. Splunk OS enrichment ───────────────────────────────────────
    if SPLUNK_CONFIG['token']:
        merged_df = enrich_with_splunk_os(merged_df, splunk_earliest, splunk_latest)
    else:
        logger.warning("SPLUNK_API_KEY not set — skipping Splunk OS enrichment.")

    # ── 6. Build files ────────────────────────────────────────────────
    safe_title = _safe_filename(title)
    xlsx_name  = f"{safe_title}_{guid}.xlsx"
    csv_name   = f"{safe_title}_{guid}.csv"

    xlsx_bytes = build_excel_bytes(workday_df, proofpoint_df, merged_df)
    csv_bytes  = build_csv_bytes(merged_df)

    # ── 7. Upload via Power Automate ──────────────────────────────────
    logger.info("Uploading Excel → ProofPoint_WorkDay_Splunk_Auto_Backup")
    upload_to_sharepoint(xlsx_bytes, xlsx_name, file_type='excel')

    logger.info("Uploading CSV → Autopipeline_MasterReports")
    upload_to_sharepoint(csv_bytes, csv_name, file_type='csv')

    # ── Summary ───────────────────────────────────────────────────────
    fp_count   = int((proofpoint_df['False Positive'] == 'TRUE').sum())
    matched    = int(merged_df['GlobalId'].notna().sum())
    unmatched  = int(merged_df['GlobalId'].isna().sum())
    exec_count = int(merged_df['Executive Leadership'].sum()) \
                 if 'Executive Leadership' in merged_df.columns else 0
    splunk_res = int((merged_df.get('splunk_os', pd.Series(dtype=str)) != '').sum()) \
                 if 'splunk_os' in merged_df.columns else 0

    logger.info("Campaign complete: pp=%d fp=%d merged=%d matched=%d "
                "unmatched=%d exec=%d splunk_resolved=%d",
                len(proofpoint_df), fp_count, len(merged_df),
                matched, unmatched, exec_count, splunk_res)
    logger.info("Excel → ProofPoint_WorkDay_Splunk_Auto_Backup/%s", xlsx_name)
    logger.info("CSV   → Autopipeline_MasterReports/%s", csv_name)
    return True

# ============================================
# MAIN
# ============================================

def main():
    logger.info("=" * 70)
    logger.info("CAMPAIGN MERGE — daily automated run (GitHub Actions)")
    logger.info("Run date (UTC): %s", datetime.now(tz=timezone.utc).strftime('%Y-%m-%d'))
    logger.info("=" * 70)

    state = load_state()
    state.setdefault('processed_guids',   [])
    state.setdefault('pending_campaigns', [])

    state = sync_pending_campaigns(state)
    ready_campaigns = get_reportable_campaigns(state)

    if not ready_campaigns:
        logger.info("No campaigns ready. %d pending (waiting for end-date + %d day buffer).",
                    len(state['pending_campaigns']), END_DATE_OFFSET_DAYS)
        save_state(state)
        sys.exit(0)

    logger.info("%d campaign(s) ready to process.", len(ready_campaigns))

    earliest_start = min(
        _parse_date(c['startDate']) for c in ready_campaigns
    ).strftime('%Y-%m-%d')

    workday_records = fetch_workday_workers(earliest_start)
    workday_df      = pd.DataFrame(workday_records)

    if workday_df.empty:
        logger.warning("No Workday records returned. Continuing with empty dataset.")
        workday_df = pd.DataFrame(columns=WORKDAY_FIELDS + ['Executive Leadership'])
    else:
        workday_df = workday_df[workday_df['InternetEmailAddress'].notna()]
        workday_df = workday_df[workday_df['InternetEmailAddress'].str.strip() != '']
        workday_df = add_executive_leadership_column(workday_df)
        logger.info("Workday: %d records (shared across %d campaign(s)).",
                    len(workday_df), len(ready_campaigns))

    succeeded, failed = [], []
    for campaign in ready_campaigns:
        try:
            ok = run_report_for_campaign(campaign, workday_df)
            (succeeded if ok else failed).append(campaign['guid'])
        except Exception as e:
            logger.exception("Unhandled error for guid=%s: %s", campaign['guid'], e)
            failed.append(campaign['guid'])

    succeeded_set = set(succeeded)
    state['pending_campaigns'] = [
        c for c in state['pending_campaigns'] if c['guid'] not in succeeded_set
    ]
    state['processed_guids'].extend(succeeded)
    save_state(state)

    logger.info("=" * 70)
    logger.info("DAILY RUN COMPLETE")
    logger.info("Succeeded : %d  %s", len(succeeded), succeeded)
    logger.info("Failed    : %d  %s  (will retry tomorrow)", len(failed), failed)
    logger.info("Pending   : %d  (waiting for end-date buffer)", len(state['pending_campaigns']))
    logger.info("Processed : %d  (all time)", len(state['processed_guids']))
    logger.info("=" * 70)

    if failed:
        sys.exit(1)


if __name__ == '__main__':
    main()