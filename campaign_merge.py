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
    'webhook_url':  os.getenv('POWER_AUTOMATE_WEBHOOK_URL'),
    'webhook_auth': os.getenv('POWER_AUTOMATE_WEBHOOK_AUTH', ''),
}

STATE_FILE             = os.getenv('STATE_FILE_PATH', 'campaign_state.json')
START_DATE_OFFSET_DAYS = int(os.getenv('START_DATE_OFFSET_DAYS', '-2'))
END_DATE_OFFSET_DAYS   = int(os.getenv('END_DATE_OFFSET_DAYS',   '3'))

LOGGING_CONFIG = {
    'level':   os.getenv('LOG_LEVEL', 'INFO').upper(),
    'use_utc': os.getenv('LOG_USE_UTC', 'true').lower() == 'true',
}

# ── Ported from manual fetcher: FirstName and LastName added for obfuscated
#    email resolution via name-matching against Workday.
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
    'PayGradeLevelCode', 'PayGradeLevelDescription',
    'FirstName', 'LastName',  # required for resolve_obfuscated_emails()
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


def compute_tenure(merged_df: pd.DataFrame, campaign_start_date: str) -> pd.DataFrame:
    """
    Add a 'Tenure' column (in decimal years, rounded to 2 dp) to merged_df.

    Logic:
      - Reference date  = campaign_start_date (the campaign's start date)
      - Anchor date     = ReHireDate if non-null, else HireDate
      - Tenure (years)  = (reference_date - anchor_date).days / 365.25
      - Negative tenures (hire date after campaign start) are left as-is so
        data anomalies remain visible; consumers can filter them out.
      - Rows where both HireDate and ReHireDate are null/unparseable get None.
    """
    try:
        ref_date = _parse_date(campaign_start_date)
    except ValueError as e:
        logger.warning("compute_tenure: cannot parse campaign_start_date '%s': %s — "
                       "Tenure set to None for all rows.", campaign_start_date, e)
        merged_df['Tenure'] = None
        return merged_df

    def _tenure_for_row(row):
        for col in ('ReHireDate', 'HireDate'):
            raw = row.get(col)
            if raw and not pd.isna(raw) and str(raw).strip():
                try:
                    anchor = _parse_date(str(raw).strip())
                    days   = (ref_date - anchor).days
                    return round(days / 365.25, 2)
                except ValueError:
                    continue
        return None

    merged_df['Tenure'] = merged_df.apply(_tenure_for_row, axis=1)

    resolved   = int(merged_df['Tenure'].notna().sum())
    unresolved = len(merged_df) - resolved
    logger.info("Tenure computed: resolved=%d unresolved=%d (ref_date=%s, "
                "anchor=ReHireDate if set, else HireDate).",
                resolved, unresolved, ref_date)
    return merged_df

# ============================================
# OBFUSCATED EMAIL RESOLUTION
# Ported from manual fetcher.
# ============================================

def resolve_obfuscated_emails(proofpoint_df: pd.DataFrame,
                               workday_df: pd.DataFrame) -> pd.DataFrame:
    """
    For every Proofpoint row whose 'Email Address' ends in '@obfuscated.invalid',
    attempt to find a matching Workday record by (FirstName, LastName) and
    replace the placeholder with the real InternetEmailAddress from Workday.
    All other Proofpoint columns remain untouched; the corrected email then
    joins correctly in the subsequent merge step.

    Matching rules:
      - Case-insensitive, whitespace-stripped comparison on both name fields.
      - Exactly ONE Workday match  → replace email, mark resolved.
      - Zero matches               → log warning, leave placeholder.
      - Multiple matches           → log warning, leave placeholder (ambiguous).

    Adds column 'Email Resolved From Obfuscated' (TRUE/FALSE) so downstream
    consumers can identify which rows were resolved this way.

    Requires FirstName and LastName in WORKDAY_FIELDS (already added above).
    """
    proofpoint_df = proofpoint_df.copy()
    proofpoint_df['Email Resolved From Obfuscated'] = 'FALSE'

    obfuscated_mask = (
        proofpoint_df['Email Address']
        .str.lower()
        .str.strip()
        .str.endswith('@obfuscated.invalid', na=False)
    )
    obfuscated_rows = proofpoint_df[obfuscated_mask]

    if obfuscated_rows.empty:
        logger.info("No obfuscated email addresses found in Proofpoint data.")
        return proofpoint_df

    logger.info("Obfuscated email resolution: %d rows to process.", len(obfuscated_rows))

    workday_name_map: dict = defaultdict(list)
    for _, wd_row in workday_df.iterrows():
        first = str(wd_row.get('FirstName')  or '').strip().lower()
        last  = str(wd_row.get('LastName')   or '').strip().lower()
        email = str(wd_row.get('InternetEmailAddress') or '').strip()
        if first and last and email:
            workday_name_map[(first, last)].append(email)

    resolved_count  = 0
    ambiguous_count = 0
    notfound_count  = 0

    for idx in obfuscated_rows.index:
        pp_first   = str(proofpoint_df.at[idx, 'First Name'] or '').strip().lower()
        pp_last    = str(proofpoint_df.at[idx, 'Last Name']  or '').strip().lower()
        orig_email = proofpoint_df.at[idx, 'Email Address']

        if not pp_first or not pp_last:
            logger.warning(
                "Row %d: obfuscated email '%s' has blank name fields — cannot resolve.",
                idx, orig_email,
            )
            notfound_count += 1
            continue

        matches = workday_name_map.get((pp_first, pp_last), [])

        if len(matches) == 1:
            proofpoint_df.at[idx, 'Email Address'] = matches[0]
            proofpoint_df.at[idx, 'Email Resolved From Obfuscated'] = 'TRUE'
            logger.info("Row %d: resolved '%s' → '%s'  (name: %s %s)",
                        idx, orig_email, matches[0],
                        pp_first.title(), pp_last.title())
            resolved_count += 1
        elif len(matches) > 1:
            logger.warning(
                "Row %d: '%s' matches %d Workday records for '%s %s' — ambiguous.",
                idx, orig_email, len(matches), pp_first.title(), pp_last.title())
            ambiguous_count += 1
        else:
            logger.warning(
                "Row %d: '%s' — no Workday record for '%s %s' — leaving placeholder.",
                idx, orig_email, pp_first.title(), pp_last.title())
            notfound_count += 1

    logger.info(
        "Obfuscated email resolution complete: resolved=%d ambiguous=%d not_found=%d",
        resolved_count, ambiguous_count, notfound_count,
    )
    return proofpoint_df

# ============================================
# AZURE FUNCTION ENRICHMENT
# ============================================


def enrich_via_azure_function(merged_df: pd.DataFrame,
                               campaign_earliest: str,
                               campaign_latest: str) -> pd.DataFrame:
    """
    Async pattern to work around the 230-second App Service HTTP timeout.

    Flow:
      1. POST action='start' with the merged data → Function runs enrichment,
         writes result blob, returns {"status":"complete","job_id":"..."}
         If the function takes longer than the HTTP timeout a 504 is returned —
         the pipeline then polls action='status' until the blob is ready.
      2. Poll action='status' every 30s until {"status":"complete"}.
      3. Fetch action='result' to get the enriched rows and delete the blob.

    The Function App's functionTimeout is 45 minutes so even large campaigns
    complete within a single invocation — the blob path handles the rare case
    where the HTTP connection drops mid-run.
    """
    function_url = os.getenv('AZURE_FUNCTION_URL')
    if not function_url:
        raise ValueError("AZURE_FUNCTION_URL is not set.")

    job_id = str(__import__('uuid').uuid4())

    # Use pandas to_json to safely serialise NaN/inf values
    merged_json = merged_df.to_json(orient='records', date_format='iso')
    start_body = json.dumps({
        'action':            'start',
        'job_id':            job_id,
        'merged_data':       json.loads(merged_json),
        'campaign_earliest': campaign_earliest,
        'campaign_latest':   campaign_latest,
    })

    logger.info("Azure Function job %s — submitting %d rows...", job_id, len(merged_df))

    # Step 1 — submit
    try:
        resp = requests.post(
            function_url,
            data=start_body,
            timeout=240,  # slightly above the 230s App Service limit
            headers={'Content-Type': 'application/json'},
        )
        if resp.status_code == 200:
            result = resp.json()
            if result.get('status') == 'complete':
                logger.info("Azure Function completed synchronously for job %s.", job_id)
                # fall through to fetch result
            else:
                raise RuntimeError(f"Unexpected start response: {result}")
        elif resp.status_code == 504:
            # HTTP connection timed out — function is still running, poll for result
            logger.info("Azure Function HTTP timeout (504) — function still running. "
                        "Polling for job %s...", job_id)
        else:
            resp.raise_for_status()
    except requests.exceptions.Timeout:
        logger.info("Azure Function HTTP connection timed out — function still running. "
                    "Polling for job %s...", job_id)

    # Step 2 — poll status until complete (up to 50 minutes)
    poll_interval = 30
    max_polls     = 100  # 100 × 30s = 50 minutes
    status_body   = json.dumps({'action': 'status', 'job_id': job_id})

    for poll in range(1, max_polls + 1):
        time.sleep(poll_interval)
        try:
            resp = requests.post(
                function_url,
                data=status_body,
                timeout=30,
                headers={'Content-Type': 'application/json'},
            )
            resp.raise_for_status()
            status = resp.json().get('status')
            logger.info("Job %s poll %d/%d — status: %s", job_id, poll, max_polls, status)
            if status == 'complete':
                break
        except requests.RequestException as exc:
            logger.warning("Job %s status poll %d failed: %s", job_id, poll, exc)
    else:
        raise RuntimeError(f"Azure Function job {job_id} did not complete within 50 minutes.")

    # Step 3 — fetch result
    result_body = json.dumps({'action': 'result', 'job_id': job_id})
    resp = requests.post(
        function_url,
        data=result_body,
        timeout=60,
        headers={'Content-Type': 'application/json'},
    )
    resp.raise_for_status()
    enriched_records = resp.json()
    if not isinstance(enriched_records, list):
        raise ValueError(f"Unexpected result type from Azure Function: {type(enriched_records)}")

    enriched_df = pd.DataFrame(enriched_records)
    logger.info("Azure Function job %s complete — %d enriched rows.", job_id, len(enriched_df))
    return enriched_df

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
    """
    Fetch all active or recently-terminated workers from Workday.
    Pulls all WORKDAY_FIELDS including FirstName, LastName (required for
    resolve_obfuscated_emails()), PayGradeLevelCode and PayGradeLevelDescription.
    """
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
# PROOFPOINT TRANSFORM
# ============================================

def transform_proofpoint_data(records: list) -> list:
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

        if clicks:
            whois_src = clicks[0]['attributes']
        elif submissions:
            whois_src = submissions[0]['attributes']
        elif attachments:
            whois_src = attachments[0]['attributes']
        else:
            whois_src = {}

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
            failed          = False
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
    """
    Left-join Proofpoint records to Workday on email address.
    Carries through 'Email Resolved From Obfuscated' if present (ported from
    manual fetcher).
    """
    logger.info("Merging Proofpoint and Workday datasets...")

    # Carry through the obfuscated-resolution flag if it was added upstream
    pp_cols = PROOFPOINT_FIELDS + (
        ['Email Resolved From Obfuscated']
        if 'Email Resolved From Obfuscated' in proofpoint_df.columns
        else []
    )

    pp = proofpoint_df[pp_cols].copy()
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
    return merged_df.to_csv(index=False, encoding='utf-8').encode('utf-8')

# ============================================
# PER-CAMPAIGN REPORT
# ============================================

def run_report_for_campaign(campaign: dict, workday_df: pd.DataFrame) -> bool:
    """
    Full pipeline for one campaign:
      1. Compute date window
      2. Fetch + transform Proofpoint
      3. Filter to this guid only
      4. Resolve obfuscated emails via Workday name-match  ← ported from manual fetcher
      5. Merge with Workday
      6. Compute Tenure
      7. Splunk OS enrichment — Azure Function (primary) or direct (fallback)
      8. Build Excel + CSV
      9. Upload via Power Automate
    """
    guid  = campaign['guid']
    title = campaign['title']

    logger.info("=" * 60)
    logger.info("Processing campaign: '%s'  guid=%s", title, guid)
    logger.info("=" * 60)

    # ── 1. Date window ────────────────────────────────────────────────
    fetch_start, fetch_end = compute_date_range(campaign)

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

    # ── 4. Resolve obfuscated emails ─────────────────────────────────
    # Rows ending in @obfuscated.invalid are matched to Workday by
    # (First Name, Last Name) so downstream merge and Splunk steps use
    # the real email address wherever possible.
    proofpoint_df = resolve_obfuscated_emails(proofpoint_df, workday_df)

    # ── 5. Merge with Workday ─────────────────────────────────────────
    merged_df = merge_datasets(proofpoint_df, workday_df)
    merged_df = merged_df[merged_df['Campaign Guid'] == guid].copy().reset_index(drop=True)

    # ── 6. Compute Tenure ─────────────────────────────────────────────
    merged_df = compute_tenure(merged_df, campaign['startDate'])

    # ── 7. Splunk OS enrichment via Azure Function ────────────────────
    # The Azure Function App proxies Splunk queries through a static IP
    # whitelisted in Splunk. Direct Splunk calls from GitHub Actions are
    # not supported — GitHub Actions IPs are dynamic and blocked by Splunk.
    if os.getenv('AZURE_FUNCTION_URL'):
        merged_df = enrich_via_azure_function(merged_df, splunk_earliest, splunk_latest)
    else:
        logger.warning("AZURE_FUNCTION_URL not set — skipping Splunk OS enrichment. "
                       "Set the secret to enable OS enrichment.")

    # ── 8. Build files ────────────────────────────────────────────────
    safe_title = _safe_filename(title)
    xlsx_name  = f"{safe_title}_{guid}.xlsx"
    csv_name   = f"{safe_title}_{guid}.csv"

    xlsx_bytes = build_excel_bytes(workday_df, proofpoint_df, merged_df)
    csv_bytes  = build_csv_bytes(merged_df)

    # ── 9. Upload via Power Automate ──────────────────────────────────
    logger.info("Uploading Excel → ProofPoint_WorkDay_Splunk_Auto_Backup")
    upload_to_sharepoint(xlsx_bytes, xlsx_name, file_type='excel')

    logger.info("Uploading CSV → Autopipeline_MasterReports")
    upload_to_sharepoint(csv_bytes, csv_name, file_type='csv')

    # ── Summary ───────────────────────────────────────────────────────
    fp_count   = int((proofpoint_df['False Positive'] == 'TRUE').sum())
    obfusc_res = int(
        (proofpoint_df.get('Email Resolved From Obfuscated',
                           pd.Series(dtype=str)) == 'TRUE').sum()
    )
    matched    = int(merged_df['GlobalId'].notna().sum())
    unmatched  = int(merged_df['GlobalId'].isna().sum())
    exec_count = int(merged_df['Executive Leadership'].sum()) \
                 if 'Executive Leadership' in merged_df.columns else 0
    splunk_res = int((merged_df.get('splunk_os', pd.Series(dtype=str)) != '').sum()) \
                 if 'splunk_os' in merged_df.columns else 0
    tenure_res = int(merged_df['Tenure'].notna().sum()) \
                 if 'Tenure' in merged_df.columns else 0

    logger.info("Campaign complete: pp=%d fp=%d obfusc_resolved=%d merged=%d "
                "matched=%d unmatched=%d exec=%d splunk_resolved=%d tenure_resolved=%d",
                len(proofpoint_df), fp_count, obfusc_res, len(merged_df),
                matched, unmatched, exec_count, splunk_res, tenure_res)
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