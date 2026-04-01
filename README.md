# Automated Pipeline for Educational Phishing Campaign Reports

Automated daily pipeline that fetches, enriches, and uploads phishing simulation campaign reports for Eli Lilly Information Security. Integrates Proofpoint Security Awareness, Workday, Splunk Cloud (via Azure Function App proxy), and SharePoint.

---

## Overview

Every day, GitHub Actions runs `campaign_merge.py` which:

1. Discovers new phishing campaigns from the Proofpoint API
2. Fetches all campaign participant records (every user sent, opened, clicked, reported)
3. Enriches each record with Workday employee data (org hierarchy, tenure, pay grade)
4. Resolves OS data from Proofpoint columns and — for users where that is absent — from Splunk via an Azure Function App proxy
5. Builds a 3-sheet Excel workbook and a flat CSV per campaign
6. Uploads both files to SharePoint via Power Automate

---

## Why an Azure Function App?

GitHub Actions runners use dynamic IP addresses that change every run. Splunk Cloud enforces an IP allowlist on port 8089 and blocks unknown IPs. Since GitHub's IPs cannot be pre-approved in Splunk, an intermediary with fixed outbound IPs is required.

The Azure Function App (`func-splunk-proxy`) runs inside a dedicated Azure VNet on a Standard S1 App Service Plan. Its outbound IPs are static and registered with Splunk. `campaign_merge.py` POSTs the merged data to the function, the function runs the Splunk queries, and returns enriched results.

### Async Pattern

Azure App Service has a hard 230-second HTTP timeout on inbound connections. Splunk enrichment for a large campaign can take 10–60 minutes. To handle this, the function uses an **async blob pattern**:

| `action` | What happens |
|---|---|
| `start` | Runs enrichment, writes result to Azure Blob Storage, returns `{"status":"complete","job_id":"..."}`. If HTTP drops after 230s, the function keeps running. |
| `status` | Checks if the result blob exists. Returns `pending` or `complete`. |
| `result` | Downloads the result blob, returns enriched rows as JSON, deletes the blob. |

The pipeline POSTs `action=start`, polls `action=status` every 30 seconds for up to 130 minutes, then fetches `action=result`.

---

## OS Enrichment — Two Stages

OS data is resolved in two stages. Stage 2 only runs for users Stage 1 could not resolve, minimising Splunk query volume.

**Stage 1 — Proofpoint columns (instant, no API calls)**
- Fill `splunk_os` from `Clicked OS` → `Email Opened OS` already present in the Proofpoint data
- `splunk_ts_source` is set to `proofpoint_column(clicked_os)` or `proofpoint_column(email_opened_os)`

**Stage 2 — Azure Function / Splunk (only for rows still empty)**
- Phase 1: Proofpoint Splunk index (`lilly_infosec_proofpoint_education`) — failure events
- Phase 2: AzureAD batch (`lilly_infosec_azuread_diagnostics`) — sign-in logs ±24h of click
- Phase 3: Single-email AzureAD retry over the full campaign window

Splunk results never overwrite Stage 1 values.

---

## Repository Structure

```
phishing-campaign-report/
├── .github/
│   └── workflows/
│       └── phishing_report.yml   # Daily scheduled workflow
├── campaign_merge.py             # Main pipeline script
├── campaign_state.json           # Persisted run state (auto-updated by workflow)
├── requirements.txt              # Python dependencies
└── README.md
```

---

## campaign_state.json

Persists across runs. Tracks:
- `processed_guids` — campaigns that have been fully processed and uploaded. Never re-processed.
- `pending_campaigns` — campaigns discovered but not yet ready (end date + 3-day buffer not reached).
- `last_run_utc` — timestamp of the last run.

The workflow commits this file back to the repository after each run with `[skip ci]` to avoid triggering a new workflow.

A campaign is considered **ready** when today's date ≥ campaign end date + `END_DATE_OFFSET_DAYS` (default: 3). This ensures all participant data is finalised in Proofpoint before reporting.

---

## Output Files

Two files are produced per campaign and uploaded to SharePoint:

| File | Destination Folder | Contents |
|---|---|---|
| `{title}_{guid}.xlsx` | `ProofPoint_WorkDay_Splunk_Auto_Backup` | 3 sheets: Workday Feed, Proofpoint Data, Merged Data |
| `{title}_{guid}.csv` | `Autopipeline_MasterReports` | Flat export of Merged Data |

Files are POSTed as base64-encoded JSON payloads to a Power Automate HTTP trigger webhook which handles the SharePoint write.

---

## Required Secrets

Set these in **Settings → Secrets and variables → Actions**:

| Secret | Description |
|---|---|
| `AZURE_CLIENT_ID` | OIDC app registration client ID |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `SUBSCRIPTION_ID` | Azure subscription ID |
| `AZURE_FUNCTION_URL` | Full Function App URL including `?code=` key — e.g. `https://func-splunk-proxy.azurewebsites.net/api/splunk_enrich?code=...` |
| `PROOFPOINT_API_KEY` | Proofpoint Security Awareness API key |
| `WORKDAY_CLIENT_ID` | Workday OAuth2 client ID |
| `WORKDAY_CLIENT_SECRET` | Workday OAuth2 client secret |
| `WORKDAY_TOKEN_URL` | Workday OAuth2 token endpoint |
| `WORKDAY_API_URL` | Workday Workers OData API base URL |
| `WORKDAY_SCOPE` | Workday OAuth2 scope |
| `POWER_AUTOMATE_WEBHOOK_URL` | Power Automate HTTP trigger URL |

---

## Environment Variables (Optional Overrides)

These can be set as repository variables or passed into the workflow to override defaults:

| Variable | Default | Description |
|---|---|---|
| `PROOFPOINT_DISCOVERY_LOOKBACK_DAYS` | `14` | How many days back to scan for new campaigns |
| `END_DATE_OFFSET_DAYS` | `3` | Days after campaign end date before processing |
| `START_DATE_OFFSET_DAYS` | `-2` | Days before campaign start date for Proofpoint fetch window |
| `SPLUNK_TIME_WINDOW_MINUTES` | `1440` | AzureAD search window around anchor event (±minutes) |
| `SPLUNK_BATCH_SIZE` | `500` | Emails per Splunk query batch |
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`) |

---

## Azure Function App

| Property | Value |
|---|---|
| Name | `func-splunk-proxy` |
| Resource Group | `rg-splunk-proxy` |
| Subscription | `dev-is-dev-cyber-tm` |
| Runtime | Python 3.11 |
| Plan | Standard S1 (Linux) — required for VNet integration and 2-hour `functionTimeout` |
| VNet | `vnet-splunk` / subnet `snet-funcapp` (10.0.1.0/24) |
| Storage | `stfuncsplunkproxy` — result blobs written to container `splunk-results` |
| `functionTimeout` | 2 hours (`00:02:00:00` in `host.json`) |

### Function App Code

The function app code is maintained separately in a local directory and deployed via Azure Functions Core Tools:

```powershell
cd C:\Users\L123065\splunk-proxy
func azure functionapp publish func-splunk-proxy --python --force
```

> The function key does not change when code is republished. `AZURE_FUNCTION_URL` remains valid across all deployments.


## Failure & Retry Behaviour

If a campaign fails for any reason (Splunk timeout, upload failure, etc.) it remains in `pending_campaigns` in `campaign_state.json` and is automatically retried on the next daily run. A campaign is only marked as permanently processed after a successful SharePoint upload.

The workflow exits with code `1` if any campaign fails, which marks the GitHub Actions run as failed for visibility.

---

## Running Manually

To trigger the pipeline for a specific lookback window:

1. Go to **Actions → phishing-campaign-report → Run workflow**
2. The workflow runs with all current secrets and the default lookback window

To force re-processing of a specific campaign, remove its GUID from `processed_guids` in `campaign_state.json` and re-run.

---

## Dependencies

```
requests
pandas
openpyxl
python-dotenv
urllib3
```

The Function App additionally requires `azure-functions` and `azure-storage-blob`.