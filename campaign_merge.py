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
    # Full URL to the phishing_extended endpoint, e.g.:
    # https://results.us.securityeducation.com/api/reporting/v0.3.0/phishing_extended
    'base_url':                   os.getenv('PROOFPOINT_BASE_URL'),
    'api_key':                    os.getenv('PROOFPOINT_API_KEY'),
    'page_size':                  int(os.getenv('PROOFPOINT_PAGE_SIZE', '500')),
    'verify_ssl':                 os.getenv('PROOFPOINT_VERIFY_SSL', 'False').lower() == 'true',
    'rate_limit_delay':           float(os.getenv('PROOFPOINT_RATE_LIMIT_DELAY', '1.0')),
    'retry_delay':                float(os.getenv('PROOFPOINT_RETRY_DELAY', '5.0')),
    'max_retries':                int(os.getenv('PROOFPOINT_MAX_RETRIES', '3')),
    # How many days back to scan for new campaigns on each daily run.
    'discovery_lookback_days':    int(os.getenv('PROOFPOINT_DISCOVERY_LOOKBACK_DAYS', '30')),
}

SHAREPOINT_CONFIG = {
    'tenant_id':     os.getenv('SHAREPOINT_TENANT_ID'),
    'client_id':     os.getenv('SHAREPOINT_CLIENT_ID'),
    'client_secret': os.getenv('SHAREPOINT_CLIENT_SECRET'),
    'site_id':       os.getenv('SHAREPOINT_SITE_ID'),
    # Separate folders for Excel and CSV outputs
    'xlsx_folder':   os.getenv('SHAREPOINT_XLSX_FOLDER', '/Reports/PhishingCampaigns/Excel'),
    'csv_folder':    os.getenv('SHAREPOINT_CSV_FOLDER',  '/Reports/PhishingCampaigns/CSV'),
}

STATE_FILE             = os.getenv('STATE_FILE_PATH', 'campaign_state.json')
START_DATE_OFFSET_DAYS = int(os.getenv('START_DATE_OFFSET_DAYS', '-2'))  # 2 days before campaign start
END_DATE_OFFSET_DAYS   = int(os.getenv('END_DATE_OFFSET_DAYS',   '3'))   # 3 days after  campaign end

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
#
# Schema:
# {
#   "processed_guids": ["guid1", "guid2"],
#   "pending_campaigns": [
#     {
#       "guid":         "abc123",
#       "title":        "Q1 Phish",
#       "startDate":    "2025-03-01",
#       "endDate":      "2025-03-07",
#       "detected_utc": "2025-03-01T10:00:00+00:00"
#     }
#   ],
#   "last_run_utc": "2025-03-08T00:00:00+00:00"
# }
#
# Lifecycle:
#   New guid detected  →  added to pending_campaigns
#   today >= endDate + END_DATE_OFFSET_DAYS  →  report generated
#   Report success  →  moved to processed_guids (never re-runs)
#   Report failure  →  stays in pending_campaigns, retried next daily run
# ============================================

def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                state = json.load(f)
            logger.info(
                "State loaded: %d processed, %d pending.",
                len(state.get('processed_guids', [])),
                len(state.get('pending_campaigns', [])),
            )
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
    """Parse ISO 8601 or YYYY-MM-DD string to a date object."""
    try:
        return datetime.fromisoformat(str(raw).replace('Z', '+00:00')).date()
    except Exception:
        raise ValueError(f"Cannot parse date: '{raw}'")


def _safe_filename(text: str) -> str:
    """Replace characters that are unsafe in filenames with underscores."""
    return ''.join(c if c.isalnum() or c in '-_ ' else '_' for c in str(text)).strip()


def parse_timestamp(ts):
    if not ts or pd.isna(ts):
        return None
    try:
        s = str(ts).replace('Z', '+00:00')
        return pd.to_datetime(s)
    except Exception as e:
        logger.warning("Failed to parse timestamp '%s': %s", ts, e)
        return None


def is_false_positive(date_sent, date_clicked, whois_isp) -> bool:
    """
    Flag a click as a false positive when:
      - Whois ISP contains 'Microsoft Azure'  AND
      - Time between sent and clicked is <= 60 seconds
    """
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
        logger.info(
            "False positive: sent=%s clicked=%s delta=%.2fs isp=%s",
            date_sent, date_clicked, delta, whois_isp,
        )
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
# CAMPAIGN DISCOVERY
# ============================================

def discover_campaigns_from_phishing_extended() -> list:
    """
    Proofpoint has no dedicated campaign-list endpoint.
    Query phishing_extended with a lookback window and extract unique
    campaigns from the event records.

    Each returned dict contains:
      guid, title, startDate (YYYY-MM-DD), endDate (YYYY-MM-DD)

    Uses filter[_includenoaction]=TRUE so campaigns with no user interactions
    are still surfaced via their 'No Action' event rows.
    """
    lookback_days = PROOFPOINT_CONFIG['discovery_lookback_days']
    today         = datetime.now(tz=timezone.utc).date()
    scan_start    = (today - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
    scan_end      = today.strftime('%Y-%m-%d')

    logger.info(
        "Discovering campaigns via phishing_extended (lookback %d days: %s → %s)...",
        lookback_days, scan_start, scan_end,
    )

    headers    = {'x-apikey-token': PROOFPOINT_CONFIG['api_key']}
    page       = 1
    seen_guids = {}   # guid → campaign dict

    while True:
        params = {
            'page[number]':                     page,
            'page[size]':                       PROOFPOINT_CONFIG['page_size'],
            'filter[_campaignstartdate_start]': scan_start,
            'filter[_campaignstartdate_end]':   scan_end,
            'filter[_includenoaction]':         'TRUE',
        }

        for attempt in range(1, PROOFPOINT_CONFIG['max_retries'] + 1):
            try:
                if page > 1 or attempt > 1:
                    time.sleep(PROOFPOINT_CONFIG['rate_limit_delay'])

                resp = requests.get(
                    PROOFPOINT_CONFIG['base_url'],
                    headers=headers,
                    params=params,
                    timeout=30,
                    verify=PROOFPOINT_CONFIG['verify_ssl'],
                )

                if resp.status_code == 429:
                    wait = int(resp.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay']))
                    logger.warning("429 Too Many Requests. Sleeping %ds.", wait)
                    time.sleep(wait)
                    continue

                resp.raise_for_status()
                data      = resp.json()
                page_data = data.get('data', [])

                for record in page_data:
                    attrs = record.get('attributes', {})
                    guid  = attrs.get('campaign_guid')
                    if not guid or guid in seen_guids:
                        continue

                    raw_start = attrs.get('campaignstartdate', '')
                    raw_end   = attrs.get('campaignenddate',   raw_start)

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

                if not page_data:
                    break   # no more pages

                page += 1
                break   # success — move to next page

            except requests.RequestException as e:
                logger.error("Discovery request error (attempt %d/%d): %s",
                             attempt, PROOFPOINT_CONFIG['max_retries'], e)
                if attempt == PROOFPOINT_CONFIG['max_retries']:
                    logger.warning("Max retries reached during discovery. Stopping.")
                    return list(seen_guids.values())
                time.sleep(PROOFPOINT_CONFIG['retry_delay'])
        else:
            break   # all retries exhausted

    campaigns = list(seen_guids.values())
    logger.info("Discovered %d unique campaign(s) in the lookback window.", len(campaigns))
    for c in campaigns:
        logger.info("  guid=%-12s start=%-12s end=%-12s title='%s'",
                    c['guid'], c['startDate'], c['endDate'], c['title'])
    return campaigns


def sync_pending_campaigns(state: dict) -> dict:
    """
    Discover campaigns from phishing_extended and add any unseen guids to
    pending_campaigns. Deduplicates against both processed_guids and
    already-pending guids so no campaign is ever queued twice.
    """
    campaigns = discover_campaigns_from_phishing_extended()
    if not campaigns:
        logger.warning("No campaigns discovered — skipping sync.")
        return state

    processed    = set(state.get('processed_guids', []))
    pending_ids  = {c['guid'] for c in state.get('pending_campaigns', [])}
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

    logger.info(
        "Sync complete: %d new queued | %d total pending | %d total processed.",
        newly_queued, len(state['pending_campaigns']), len(processed),
    )
    return state


def get_reportable_campaigns(state: dict) -> list:
    """
    Return pending campaigns where:
      today (UTC) >= endDate + END_DATE_OFFSET_DAYS

    Campaigns whose end date has not yet passed (plus the buffer) remain
    in pending and will be checked again on the next daily run.
    """
    today = datetime.now(tz=timezone.utc).date()
    ready, waiting = [], []

    for c in state.get('pending_campaigns', []):
        try:
            end_date   = _parse_date(c.get('endDate') or c.get('startDate', ''))
            ready_date = end_date + timedelta(days=END_DATE_OFFSET_DAYS)
        except ValueError as e:
            logger.warning("Skipping campaign guid=%s — bad date: %s", c.get('guid'), e)
            continue

        if today >= ready_date:
            logger.info(
                "READY   guid=%s endDate=%s readyDate=%s today=%s",
                c['guid'], end_date, ready_date, today,
            )
            ready.append(c)
        else:
            days_left = (ready_date - today).days
            logger.info(
                "WAITING guid=%s endDate=%s readyDate=%s today=%s (%d day(s) remaining)",
                c['guid'], end_date, ready_date, today, days_left,
            )
            waiting.append(c)

    logger.info(
        "%d campaign(s) ready to report | %d still waiting.",
        len(ready), len(waiting),
    )
    return ready


def compute_date_range(campaign: dict) -> tuple:
    """
    Proofpoint query window for a single campaign:
      fetch_start = startDate + START_DATE_OFFSET_DAYS  (negative → before)
      fetch_end   = endDate   + END_DATE_OFFSET_DAYS    (positive → after)
    Returns (fetch_start, fetch_end) as 'YYYY-MM-DD' strings.
    """
    campaign_start = _parse_date(campaign['startDate'])
    campaign_end   = _parse_date(campaign.get('endDate') or campaign['startDate'])

    fetch_start = (campaign_start + timedelta(days=START_DATE_OFFSET_DAYS)).strftime('%Y-%m-%d')
    fetch_end   = (campaign_end   + timedelta(days=END_DATE_OFFSET_DAYS)).strftime('%Y-%m-%d')

    logger.info(
        "Campaign window: %s → %s | Fetch window: %s → %s",
        campaign_start, campaign_end, fetch_start, fetch_end,
    )
    return fetch_start, fetch_end

# ============================================
# SHAREPOINT UPLOAD  (Microsoft Graph API)
# ============================================

def get_sharepoint_token() -> str:
    url = (
        f"https://login.microsoftonline.com/"
        f"{SHAREPOINT_CONFIG['tenant_id']}/oauth2/v2.0/token"
    )
    resp = requests.post(
        url,
        data={
            'grant_type':    'client_credentials',
            'client_id':     SHAREPOINT_CONFIG['client_id'],
            'client_secret': SHAREPOINT_CONFIG['client_secret'],
            'scope':         'https://graph.microsoft.com/.default',
        },
        timeout=30,
    )
    resp.raise_for_status()
    logger.info("SharePoint Graph token acquired.")
    return resp.json()['access_token']


def _ensure_sharepoint_folder(headers: dict, graph_base: str, site_id: str, folder_path: str):
    """
    Verify that folder_path already exists in SharePoint.
    Raises FileNotFoundError if it does not — prevents silent typos in
    SHAREPOINT_XLSX_FOLDER / SHAREPOINT_CSV_FOLDER from going unnoticed.
    """
    probe_url = f"{graph_base}/sites/{site_id}/drive/root:{folder_path}"
    resp      = requests.get(probe_url, headers=headers, timeout=30)

    if resp.status_code == 200:
        logger.info("SharePoint folder confirmed: %s", folder_path)
        return

    if resp.status_code == 404:
        raise FileNotFoundError(
            f"SharePoint folder not found: '{folder_path}'. "
            "Check SHAREPOINT_XLSX_FOLDER / SHAREPOINT_CSV_FOLDER. "
            "Path must be relative to the site root, e.g. "
            "'/Shared Documents/Reports/Excel'."
        )

    resp.raise_for_status()


def upload_to_sharepoint(file_bytes: bytes, filename: str, folder_path: str):
    """
    Upload file_bytes to the specified SharePoint folder via Microsoft Graph.
      ≤ 4 MB  →  simple PUT
      > 4 MB  →  resumable upload session (3 MB chunks)
    """
    token      = get_sharepoint_token()
    headers    = {'Authorization': f'Bearer {token}'}
    graph_base = 'https://graph.microsoft.com/v1.0'
    site_id    = SHAREPOINT_CONFIG['site_id']

    _ensure_sharepoint_folder(headers, graph_base, site_id, folder_path)

    item_path  = f"{folder_path.rstrip('/')}/{filename}"
    upload_url = f"{graph_base}/sites/{site_id}/drive/root:{item_path}:/content"
    four_mb    = 4 * 1024 * 1024

    if len(file_bytes) <= four_mb:
        resp = requests.put(
            upload_url,
            headers={**headers, 'Content-Type': 'application/octet-stream'},
            data=file_bytes,
            timeout=60,
        )
        resp.raise_for_status()
        logger.info(
            "Uploaded '%s' → '%s' (simple, %d bytes).",
            filename, folder_path, len(file_bytes),
        )
    else:
        session_resp = requests.post(
            f"{graph_base}/sites/{site_id}/drive/root:{item_path}:/createUploadSession",
            headers={**headers, 'Content-Type': 'application/json'},
            json={'item': {'@microsoft.graph.conflictBehavior': 'replace'}},
            timeout=30,
        )
        session_resp.raise_for_status()
        session_upload_url = session_resp.json()['uploadUrl']

        chunk_size    = 3 * 1024 * 1024   # must be a multiple of 320 KiB
        total, offset = len(file_bytes), 0

        while offset < total:
            end   = min(offset + chunk_size, total)
            chunk = file_bytes[offset:end]
            requests.put(
                session_upload_url,
                headers={
                    'Content-Length': str(len(chunk)),
                    'Content-Range':  f'bytes {offset}-{end - 1}/{total}',
                },
                data=chunk,
                timeout=120,
            ).raise_for_status()
            logger.info("Chunk uploaded: bytes %d-%d / %d", offset, end - 1, total)
            offset = end

        logger.info(
            "Uploaded '%s' → '%s' (resumable, %d bytes).",
            filename, folder_path, total,
        )

# ============================================
# WORKDAY API
# ============================================

def get_workday_access_token() -> str:
    logger.info("Requesting Workday access token...")
    resp = requests.post(
        WORKDAY_CONFIG['token_url'],
        data={
            'grant_type':    'client_credentials',
            'client_id':     WORKDAY_CONFIG['client_id'],
            'client_secret': WORKDAY_CONFIG['client_secret'],
            'scope':         WORKDAY_CONFIG['scope'],
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    resp.raise_for_status()
    logger.info("Workday token acquired.")
    return resp.json()['access_token']


def fetch_workday_workers(campaign_start_date: str) -> list:
    """
    Fetch all workers who are either:
      - Active, OR
      - Terminated on or after campaign_start_date
    Paginated at 1,000 records per page.
    """
    logger.info(
        "Fetching Workday workers (active OR terminated >= %s)...",
        campaign_start_date,
    )
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
        url = (
            f"{WORKDAY_CONFIG['api_url']}?{filter_q}"
            f"&$select={select_fields}&$top={page_size}&$skip={skip}"
        )
        try:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            records = resp.json().get('value', [])
            if not records:
                break
            all_records.extend(records)
            logger.info("Workday page: +%d (total so far: %d)", len(records), len(all_records))
            skip += page_size
        except requests.RequestException as e:
            logger.error("Workday fetch error: %s", e)
            break

    logger.info("Total Workday records fetched: %d", len(all_records))
    return all_records

# ============================================
# PROOFPOINT API
# ============================================

def fetch_proofpoint_records(start_date: str, end_date: str) -> list:
    """
    Fetch all Proofpoint phishing records for the given date window.
    Uses filter[_campaignstartdate_start/end] so the window is anchored to
    campaign start date, not event timestamp.
    Includes no-action users and deleted users for full parity with the UI.
    Validates fetched count against meta.count to detect partial fetches.
    """
    logger.info("Fetching Proofpoint records (%s → %s)...", start_date, end_date)
    all_records, page_number = [], 1
    has_more_pages, expected_total = True, None
    headers = {'x-apikey-token': PROOFPOINT_CONFIG['api_key']}

    while has_more_pages:
        params = {
            'page[number]':                      page_number,
            'page[size]':                        PROOFPOINT_CONFIG['page_size'],
            'filter[_campaignstartdate_start]':  start_date,
            'filter[_campaignstartdate_end]':    end_date,
            'filter[_includenoaction]':          'TRUE',
            'filter[_includedeletedusers]':      'TRUE',
        }

        for attempt in range(1, PROOFPOINT_CONFIG['max_retries'] + 1):
            try:
                if page_number > 1 or attempt > 1:
                    time.sleep(PROOFPOINT_CONFIG['rate_limit_delay'])

                resp = requests.get(
                    PROOFPOINT_CONFIG['base_url'],
                    headers=headers,
                    params=params,
                    timeout=30,
                    verify=PROOFPOINT_CONFIG['verify_ssl'],
                )

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
                        logger.info("Proofpoint reports total records: %s", expected_total)

                page_data = data.get('data', [])
                if page_data:
                    all_records.extend(page_data)
                    logger.info(
                        "Proofpoint page %d: +%d (total so far: %d)",
                        page_number, len(page_data), len(all_records),
                    )
                    page_number += 1
                else:
                    has_more_pages = False
                break   # successful response — exit retry loop

            except requests.RequestException as e:
                logger.error("Proofpoint request error (attempt %d/%d): %s",
                             attempt, PROOFPOINT_CONFIG['max_retries'], e)
                if attempt == PROOFPOINT_CONFIG['max_retries']:
                    has_more_pages = False
                else:
                    time.sleep(PROOFPOINT_CONFIG['retry_delay'])

    logger.info("Total Proofpoint records fetched: %d", len(all_records))
    if expected_total and len(all_records) < int(expected_total):
        logger.warning(
            "Partial fetch detected: expected %s, got %d. Output may be incomplete.",
            expected_total, len(all_records),
        )
    return all_records

# ============================================
# PROOFPOINT TRANSFORM
# ============================================

def transform_proofpoint_data(records: list) -> list:
    """
    Group raw Proofpoint events by user_guid + campaign_guid.
    Detects false positives (Microsoft Azure click within 60 s of send).
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

        ctype = first.get('campaigntype', '')
        if   ctype == 'Drive By':             failed = bool(clicks)
        elif ctype == 'Data Entry Campaign':  failed = bool(submissions)
        elif ctype == 'Attachment':           failed = bool(attachments)
        else:                                 failed = False

        whois_src = (
            clicks or submissions or attachments or views
            or [{'attributes': first}]
        )[0]['attributes']

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
            'Whois ISP':                    whois_isp,
            'Whois Country':                whois_src.get('whois_country'),
            'Teachable Moment Started':     b(tm_sent),
            'Acknowledgement Completed':    b(tm_done),
            'False Positive':               b(is_fp),
        })

    logger.info(
        "Transform complete: %d unique user-campaign records (%d false positives).",
        len(transformed), fp_count,
    )
    return transformed

# ============================================
# MERGE
# ============================================

def merge_datasets(proofpoint_df: pd.DataFrame, workday_df: pd.DataFrame) -> pd.DataFrame:
    """Left-join Proofpoint data onto Workday on email address (case-insensitive)."""
    logger.info("Merging Proofpoint and Workday datasets...")

    pp = proofpoint_df[PROOFPOINT_FIELDS].copy()
    wd = workday_df[WORKDAY_FIELDS + ['Executive Leadership']].copy()

    pp['Email Address']        = pp['Email Address'].str.lower().str.strip()
    wd['InternetEmailAddress'] = wd['InternetEmailAddress'].str.lower().str.strip()

    merged = pd.merge(
        pp, wd,
        left_on='Email Address',
        right_on='InternetEmailAddress',
        how='left',
        suffixes=('_Proofpoint', '_Workday'),
    )
    merged.drop(columns=['InternetEmailAddress'], errors='ignore', inplace=True)

    matched   = int(merged['GlobalId'].notna().sum())
    unmatched = int(merged['GlobalId'].isna().sum())
    logger.info("Merge complete: %d rows | matched=%d | unmatched=%d", len(merged), matched, unmatched)
    return merged

# ============================================
# FILE BUILDERS  (in-memory, no local disk)
# ============================================

def build_excel_bytes(workday_df: pd.DataFrame,
                      proofpoint_df: pd.DataFrame,
                      merged_df: pd.DataFrame) -> bytes:
    """
    Build a 3-sheet Excel workbook in memory.
      Sheet 1 — Workday Feed    : full employee roster used for the merge
      Sheet 2 — Proofpoint Data : campaign-filtered phishing event records
      Sheet 3 — Merged Data     : campaign-filtered records enriched with Workday data
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
    """Serialise the merged DataFrame to UTF-8 CSV bytes."""
    return merged_df.to_csv(index=False, encoding='utf-8').encode('utf-8')

# ============================================
# PER-CAMPAIGN REPORT
# ============================================

def run_report_for_campaign(campaign: dict, workday_df: pd.DataFrame) -> bool:
    """
    End-to-end report generation for a single campaign:
      1. Compute fetch date window
      2. Fetch + transform Proofpoint records
      3. Filter strictly to this campaign guid only
      4. Merge with Workday
      5. Build <CampaignTitle>_<CampaignGuid>.xlsx → xlsx_folder
         Build <CampaignTitle>_<CampaignGuid>.csv  → csv_folder
      6. Upload both files to their respective SharePoint folders
    Returns True on success, False on any failure.
    """
    guid  = campaign['guid']
    title = campaign['title']

    logger.info("=" * 60)
    logger.info("Processing campaign: '%s'  guid=%s", title, guid)
    logger.info("=" * 60)

    # ── 1. Date window ────────────────────────────────────────────────
    fetch_start, fetch_end = compute_date_range(campaign)

    # ── 2. Fetch + transform Proofpoint ──────────────────────────────
    pp_records = fetch_proofpoint_records(fetch_start, fetch_end)
    if not pp_records:
        logger.error("No Proofpoint records returned for campaign %s. Skipping.", guid)
        return False

    all_proofpoint_df = pd.DataFrame(transform_proofpoint_data(pp_records))

    # ── 3. Filter to this campaign guid only ──────────────────────────
    proofpoint_df = all_proofpoint_df[
        all_proofpoint_df['Campaign Guid'] == guid
    ].copy()

    if proofpoint_df.empty:
        logger.warning(
            "No records match campaign guid=%s after filtering. "
            "The date window returned records for other campaigns only.",
            guid,
        )
        return False

    logger.info(
        "Records for this campaign: %d (of %d total in date window).",
        len(proofpoint_df), len(all_proofpoint_df),
    )

    # ── 4. Merge ──────────────────────────────────────────────────────
    merged_df = merge_datasets(proofpoint_df, workday_df)
    merged_df = merged_df[merged_df['Campaign Guid'] == guid].copy()

    # ── 5. Filenames:  <CampaignTitle>_<CampaignGuid>.xlsx / .csv ─────
    safe_title = _safe_filename(title)
    xlsx_name  = f"{safe_title}_{guid}.xlsx"
    csv_name   = f"{safe_title}_{guid}.csv"

    xlsx_bytes = build_excel_bytes(workday_df, proofpoint_df, merged_df)
    csv_bytes  = build_csv_bytes(merged_df)

    # ── 6. Upload to separate SharePoint folders ──────────────────────
    logger.info("Uploading Excel → %s/%s", SHAREPOINT_CONFIG['xlsx_folder'], xlsx_name)
    upload_to_sharepoint(xlsx_bytes, xlsx_name, SHAREPOINT_CONFIG['xlsx_folder'])

    logger.info("Uploading CSV   → %s/%s", SHAREPOINT_CONFIG['csv_folder'], csv_name)
    upload_to_sharepoint(csv_bytes,  csv_name,  SHAREPOINT_CONFIG['csv_folder'])

    # ── Summary ───────────────────────────────────────────────────────
    fp_count   = int((proofpoint_df['False Positive'] == 'TRUE').sum())
    matched    = int(merged_df['GlobalId'].notna().sum())
    unmatched  = int(merged_df['GlobalId'].isna().sum())
    exec_count = int(merged_df['Executive Leadership'].sum()) if 'Executive Leadership' in merged_df.columns else 0

    logger.info(
        "Campaign complete: rows=%d fp=%d merged=%d matched=%d unmatched=%d exec=%d",
        len(proofpoint_df), fp_count, len(merged_df), matched, unmatched, exec_count,
    )
    return True

# ============================================
# MAIN
# ============================================

def main():
    logger.info("=" * 70)
    logger.info("CAMPAIGN MERGE — daily automated run (GitHub Actions)")
    logger.info("Run date (UTC): %s", datetime.now(tz=timezone.utc).strftime('%Y-%m-%d'))
    logger.info("=" * 70)

    # ── 1. Load state ─────────────────────────────────────────────────────
    state = load_state()
    state.setdefault('processed_guids',   [])
    state.setdefault('pending_campaigns', [])

    # ── 2. Discover all campaigns in the lookback window and queue new ones ─
    state = sync_pending_campaigns(state)

    # ── 3. Check which pending campaigns are ready to report ──────────────
    #       Ready = today (UTC) >= campaign endDate + END_DATE_OFFSET_DAYS
    ready_campaigns = get_reportable_campaigns(state)

    if not ready_campaigns:
        logger.info(
            "No campaigns ready to report today. "
            "%d campaign(s) still waiting for their end-date + %d day buffer.",
            len(state['pending_campaigns']), END_DATE_OFFSET_DAYS,
        )
        save_state(state)
        sys.exit(0)

    logger.info("%d campaign(s) ready to process today.", len(ready_campaigns))

    # ── 4. Fetch Workday ONCE — shared across all campaigns this run ───────
    #       Use the earliest campaign startDate as the termination lower bound
    #       so terminated workers from the oldest campaign are included.
    earliest_start = min(
        _parse_date(c['startDate']) for c in ready_campaigns
    ).strftime('%Y-%m-%d')

    workday_records = fetch_workday_workers(earliest_start)
    workday_df      = pd.DataFrame(workday_records)

    if workday_df.empty:
        logger.warning("No Workday records returned. Continuing with empty Workday dataset.")
        workday_df = pd.DataFrame(columns=WORKDAY_FIELDS + ['Executive Leadership'])
    else:
        workday_df = workday_df[workday_df['InternetEmailAddress'].notna()]
        workday_df = workday_df[workday_df['InternetEmailAddress'].str.strip() != '']
        workday_df = add_executive_leadership_column(workday_df)
        logger.info(
            "Workday: %d records fetched (shared across %d campaign(s)).",
            len(workday_df), len(ready_campaigns),
        )

    # ── 5. Generate a report for each ready campaign ──────────────────────
    succeeded, failed = [], []

    for campaign in ready_campaigns:
        try:
            ok = run_report_for_campaign(campaign, workday_df)
            (succeeded if ok else failed).append(campaign['guid'])
        except Exception as e:
            logger.exception(
                "Unhandled error for campaign guid=%s: %s", campaign['guid'], e
            )
            failed.append(campaign['guid'])

    # ── 6. Update state ───────────────────────────────────────────────────
    #       Succeeded → processed_guids (never re-run)
    #       Failed    → remain in pending_campaigns (retried tomorrow)
    succeeded_set = set(succeeded)
    state['pending_campaigns'] = [
        c for c in state['pending_campaigns']
        if c['guid'] not in succeeded_set
    ]
    state['processed_guids'].extend(succeeded)
    save_state(state)

    # ── 7. Final run summary ──────────────────────────────────────────────
    logger.info("=" * 70)
    logger.info("DAILY RUN COMPLETE")
    logger.info("Succeeded : %d  %s", len(succeeded), succeeded)
    logger.info("Failed    : %d  %s  (will retry tomorrow)", len(failed), failed)
    logger.info("Pending   : %d  (waiting for end-date buffer)", len(state['pending_campaigns']))
    logger.info("Processed : %d  (all time)", len(state['processed_guids']))
    logger.info("=" * 70)

    # Non-zero exit marks the GitHub Actions run as failed so the team is alerted
    if failed:
        sys.exit(1)


if __name__ == '__main__':
    main()