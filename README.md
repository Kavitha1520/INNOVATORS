# BRANDSHIELD AI
                 BRANDSHIELD AI
          AI-Powered Brand Protection Platform
                          |
          ┌───────────────┴────────────────┐
          │                                │
    1. USER INTERFACE                2. ADMIN INTERFACE
          │                                │
          └───────────────┬────────────────┘
                          |
                 REACT + TYPESCRIPT
                    FRONTEND
                          |
                HTTP / REST API
                          |
                 FASTAPI BACKEND
                          |
          ┌───────────────┴────────────────┐
          │                                │
    AUTHENTICATION                   API ROUTES
          │                                │
    Role Permissions          ┌─────────────┼─────────────┐
                              │             │             │
                         Brand Module   Detection      Reports
                              │             │             │
                              └─────────────┼─────────────┘
                                            |
                               THREAT ANALYSIS ENGINE
                                            |
                 ┌──────────────────────────┼────────────────────┐
                 │                          │                    │
           URL Analysis               QR Analysis           OCR Analysis
                 │                          │                    │
                 └──────────────────────────┼────────────────────┘
                                            |
                                  AI / THREAT INTELLIGENCE
                                            |
                            NVIDIA HOSTED LLAMA MODEL
                                            |
                                  RESULTS & RISK SCORES
                                            |
                              SQLITE DATABASE
                                            |
                 ┌──────────────────────────┼────────────────────┐
                 │                          │                    │
            Brand Records             Detection Records      Audit Logs
                 │                          │                    │
                 └──────────────────────────┼────────────────────┘
                                            |
                                  DASHBOARD & REPORTS







Local-first digital risk protection demo with a React/Vite frontend, FastAPI API, and SQLite storage.

## Run locally

In the project root:

```powershell
npm install
python -m pip install -r backend/requirements.txt
npm --prefix frontend install
npm run dev
```

Open `http://localhost:5173`. The frontend starts a local demo analyst session automatically. For direct API use, `POST /api/auth/login` with:

- Email: `analyst@brandshield.local`
- Password: `brandshield-demo`

The API is served on `http://localhost:8000`. The SQLite database is at `backend/db/brandshield.db`.

## Implemented architecture

- Session authentication uses expiring HMAC-signed bearer tokens; passwords are stored as PBKDF2 hashes. Mutations require the admin/owner role.
- Set `BRANDSHIELD_TOKEN_SECRET` to a private random value of at least 32 characters before a company pilot. Generate one in PowerShell with `$env:BRANDSHIELD_TOKEN_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(48))")` and keep it stable across backend restarts. Outside local development, startup fails if the secret is missing; local development uses a random process-only secret, which invalidates sessions on restart.
- Organization and user, brand, configured monitoring source, finding, evidence, entity, relationship, investigation, audit, and report-metadata tables are persisted in SQLite.
- Investigations can link to findings within the same brand. Startup applies an additive migration for this optional link; deleting a finding unlinks it from investigations while retaining the investigations and audit history.
- `POST /api/analysis/analyze` performs local fuzzy-name matching, URL structure checks, solicitation phrase checks, optional application metadata checks, and optional perceptual logo-hash comparison. It returns a heuristic risk score/category, indicators, evidence, and an explanation; `suspicious` is not confirmation of fraud. URL inputs are validated and analyzed without opening/fetching them or querying external reputation services. If enabled and reachable locally, Ollama embeddings are used only as an additional text-similarity signal; deterministic fuzzy/rule analysis remains the fallback.
- The detection rules are regression-tested against a small static labeled dataset in `backend/tests/data/detection_accuracy_cases.json`. It includes explicit credential requests, coercive account-recovery text, gift-card payment demands, and benign urgency/verification wording. Its metrics are synthetic test results only and do not establish real-world accuracy.
- `GET /api/scam-dna/graph` builds a NetworkX relationship graph from saved brands, findings, evidence, entities, reports, campaigns, and QR checks. It omits cross-brand links that do not match their stored brand references; the Scam DNA view supports selecting nodes to inspect record details and stored relationship types.
- CSV findings export is available from Reports. Ollama is disabled by default; enable `OLLAMA_ENABLED` and configure a local embedding model to opt in.
- The Customer Scam Reporting Portal accepts reports and optional screenshots; when local Tesseract OCR is available, extracted screenshot text is assessed by the same heuristic analysis pipeline and shown with its evidence. Without Tesseract, the image is validated, the API reports OCR as unavailable with setup guidance, and manually entered report text remains usable.
- AI Chat is available from the primary navigation and calls the authenticated `POST /api/ai/chat` endpoint. The backend uses the NVIDIA-hosted `meta/llama-3.2-11b-vision-instruct` model and reads `NVIDIA_API_KEY` only from the backend environment/root `.env`; it is never sent to the browser. Set the key in `.env` and restart the backend. The chat reports missing configuration, invalid credentials, quota/rate-limit responses, provider errors, and connection timeouts without exposing the key.
- CSV candidate ingestion is available from Social Monitoring and App Monitoring. Upload a UTF-8 CSV with a `name` or `entity_name` column and optional `url`, `platform`, and `description` columns.
- QR Safety decodes an uploaded QR image locally with OpenCV and assesses HTTP(S) URLs using local URL heuristics. Non-URL and malformed URL content is returned as inconclusive instead of being treated as a web threat. QR content and URLs are never opened or fetched.
- Campaign Evolution groups analyzed findings only by an exactly shared domain that the URL heuristics classify as suspicious; matching solicitation phrases alone do not establish a campaign. Legacy phrase-only campaign records are retained in storage but excluded from the campaign timeline. Timelines preserve historical events after linked findings are deleted or replaced, while current finding counts and risk summaries reflect only findings that still exist. Investigation Copilot provides local, rules-based response guidance.
- Brand Trust Center lists owner-configured official websites, domains, social accounts, and mobile apps. This is a directory, not an external ownership-verification service.
- Website/domain threat monitoring supports an opt-in PhishTank `online-valid` feed connector. Register for a free PhishTank API key, set `PHISHTANK_API_KEY` in the root `.env`, restart the backend, then enable the feed for a brand in Social Monitoring. The connector requests only PhishTank's fixed feed endpoint; suspicious indicator URLs are never opened. Findings are created only for active, verified feed records whose target exactly matches the brand name, with the source and provider timestamps stored as evidence. Per-brand feed runs can be scheduled hourly, every 6/12 hours, or daily. The UI reports configuration and connection state; `LIVE` is reported only after a successful feed fetch. Feed access and quotas remain subject to PhishTank's current terms and API limits.

## Demo scope

Bundled findings are labelled simulated demonstration data. Configured social/app sources are saved as monitoring inputs, but this demo does not crawl social networks or app stores; those services require platform-specific compliant connectors and are not represented as live monitoring. Telegram monitoring is not implemented because available access and usage terms need to be validated for this AI-analysis use case. Instagram monitoring is not implemented; official Meta API access is limited to configured professional accounts and granted permissions. Analysts can submit candidate profiles/apps for local analysis in the Social Monitoring and App Monitoring screens.

For Phase 1 feed setup, add `PHISHTANK_API_KEY=<your key>` to the ignored root `.env` file and restart the backend. A key is required for the PhishTank feed, but no external AI API key is used. Do not put feed credentials in frontend code or source control. Feed requests have a fixed host, a 20-second timeout, and a bounded response size; HTTP errors and provider rate limits are surfaced without logging the credential.

OCR depends on a locally installed Tesseract executable in addition to the Python package. On Windows, download the [official Tesseract 5.5.3 Windows installer](https://github.com/tesseract-ocr/tesseract/releases/download/5.5.3/tesseract-ocr-w64-setup-5.5.3.20260724.exe) and run it. If Windows requests administrator approval, complete the installation from an administrator account; this project does not bypass installer permissions. Verify the default installation with `& "C:\Program Files\Tesseract-OCR\tesseract.exe" --version`. If the executable is elsewhere or not on `PATH`, set `TESSERACT_CMD` to its full path before starting the backend:

```powershell
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
npm run dev
```

To save the setting for future terminals, run `[Environment]::SetEnvironmentVariable("TESSERACT_CMD", "C:\Program Files\Tesseract-OCR\tesseract.exe", "User")`, then fully restart VS Code so the backend inherits it. Install the Python dependencies with `python -m pip install -r backend\requirements.txt` if needed. The Settings page reports OCR availability; when Tesseract is missing, the API reports the dependency clearly and screenshot reports can still be submitted with manually entered text. QR decoding requires the OpenCV package listed in `backend/requirements.txt`.
