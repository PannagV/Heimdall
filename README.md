# Project Heimdall

Heimdall is a Linux-based SIEM focused on collecting Suricata network security events, normalizing them into a consistent JSON format, and storing them in MongoDB for search, dashboards, and incident workflows.

It tails Suricata logs in real time, parse and normalize events, and expose the latest alerts and stored events through a UI and API.

## Core features

- **Suricata control**
  - Start and stop Suricata from the web UI/API.
  - Select the network interface and Suricata config path.
  - Supports Suricata log types `eve.json` and `fast.log`.

- **Real-time log ingestion**
  - A background tailer follows the selected Suricata log file and handles log rotation.
  - Each new line is parsed and converted into a normalized event structure.

- **Normalization with HCES**
  - Events are normalized into the **Heimdall Common Event Schema (HCES)**.
  - Each stored document includes:
    - A generated `event_id`
    - `timestamp` and `ingested_at`
    - An `event` block (`kind`, `category`, `type`, `severity`, `outcome`)
    - `sensor` context
    - Optional `source`, `destination`, `network`, `alert`, and `file` context when present
    - A preserved copy of the original event under `raw_event`

- **Schema validation**
  - HCES can be validated against `hces_schema.json` before insertion.
  - MongoDB collections are created (or updated) with JSON schema validators to reduce malformed writes.

- **MongoDB storage and indexes**
  - Data is stored in MongoDB database `alerts`.
  - Primary collections include:
    - `events` for normalized events
    - `incidents` for correlated incident records
    - `users`, `refresh_tokens`, and `audit_logs` for authentication and auditing
  - Indexes are created for common query paths such as timestamps, IPs, severity, alert IDs, and incident IDs.

- **Alert buffering and streaming**
  - The server keeps a rolling in-memory buffer of recent alerts for the UI.
  - Alerts can be fetched in batches or streamed to the browser.

- **Correlation and incident workflow**
  - A correlation engine loads rules from `correlation_rules.json` (path configurable) and can enrich events and group related activity into incidents.
  - Incidents are tracked with timestamps, status, entities, and references to related events.
  - There is a background incident closer that can automatically close inactive incidents based on configuration.

- **Metrics and dashboard views**
  - The UI shows summaries like total alerts, last 24 hours, severity breakdown, top signatures, and trend data computed from MongoDB.

- **Authentication and roles**
  - API endpoints under `/api/` are protected with JWT-based authentication.
  - Roles are enforced (viewer, analyst, admin).
  - Refresh tokens are stored as hashes, and audit logs record authentication actions.
  - Basic rate limiting is applied to reduce brute-force attempts.

- **Integrations (optional)**
  - The codebase includes an integration layer that can dispatch incident notifications to external systems such as Jira and Slack when configured.

## New Feature: Heimdall AI SOC Copilot

Many SIEMs push every raw log through heavy machine learning in the background. This can create high compute costs, too many low-quality alerts, and decisions that are hard to explain.

Heimdall introduces an **on-demand AI SOC Copilot** to support investigations without constant background inference. Instead of running AI on every event, analysts select a suspicious set of events and request an AI review. This keeps AI usage focused on cases where an analyst believes it is needed.

### Key capabilities

- **Context-aware severity scoring:** Reviews analyst-selected event chains and assigns severity based on the full sequence, not a single log line.
- **Automated MITRE ATT&CK mapping:** Maps selected telemetry to relevant MITRE tactics and techniques.
- **Explainable assessments:** Produces structured output with clear reasoning for each assessment, so analysts can review why a score or mapping was chosen.
- **Bounded execution:** Runs only on evidence selected by the analyst. This limits cost, reduces uncontrolled queries, and helps reduce hallucinations.

### Under the hood

The Copilot is designed as a decoupled feature:

- **Frontend (Angular):** A split-pane investigation view for selecting raw logs and reviewing structured AI output.
- **Backend (Python):** A REST API that gathers selected telemetry, formats prompts, and enforces JSON schema contracts so the UI can render results reliably.

## Data model overview (HCES)

HCES is designed to keep event storage consistent across sources while still preserving the original payload.

- Required top-level fields include:
  - `event_id`, `timestamp`, `ingested_at`, `event`, `source_type`, `sensor`, `raw_event`
- Common optional blocks:
  - `source`, `destination`, `network`, `alert`, `file`, `incident`, `threat`

The schema definition lives in [hces_schema.json](hces_schema.json).

## Suricata event handling

Heimdall supports two Suricata log formats:

- **EVE JSON (`eve.json`)**
  - Parses Suricata EVE events.
  - Alerts become `event.kind = "alert"` and include an `alert` block (signature ID, signature text, category, severity, action).
  - Other EVE events are stored as `event.kind = "event"` with network context when available.
  - The full original EVE object is stored under `raw_event.data`.

- **Fast log (`fast.log`)**
  - Parses fast.log lines into alert events.
  - Extracts source/destination IP and port when present.
  - Stores the original raw line under `raw_event.data`.

Severity is normalized to a 1–5 scale for consistent filtering and reporting.

## Environment variables

Configuration is driven primarily by environment variables:

- `SURICATA_CONFIG` (default: `/etc/suricata/suricata.yaml`)
- `SURICATA_IFACE` (default: `enp0s3`)
- `SURICATA_LOG_DIR` (default: `/var/log/suricata`)
- `SURICATA_LOG_TYPE` (default: `eve.json`)
- `MONGO_URI` (default: `mongodb://localhost:27017`)
- `HEIMDALL_SENSOR_ID` (default: `sensor-1`)
- `HEIMDALL_SENSOR_HOSTNAME` (default: system hostname)

Correlation, authentication, and integration settings are also configurable (for example rule path, token settings, Jira, and Slack).

## Notes

- Heimdall is built around the idea that normalized events should be easy to query while still keeping the original evidence intact under `raw_event`.
- New sources can be added by implementing a parser that outputs HCES-compatible documents without changing the storage model.

<img width="1202" height="611" alt="image" src="https://github.com/user-attachments/assets/6a416349-1d52-4d76-b9d5-4cb4a3fee4ff" />
<img width="1197" height="602" alt="image" src="https://github.com/user-attachments/assets/700a3b2b-c56e-40b7-a109-a3f72b0cbb8c" />
<img width="1208" height="621" alt="image" src="https://github.com/user-attachments/assets/860280c8-57d0-4778-a096-46d8c3b7df4a" />
<img width="1527" height="778" alt="image" src="https://github.com/user-attachments/assets/2593151b-1fed-4b2f-b90e-6504fe491673" />
<img width="1527" height="778" alt="image" src="https://github.com/user-attachments/assets/3d0b656b-7b15-4fa9-abcc-7baea64186df" />
<img width="1527" height="778" alt="image" src="https://github.com/user-attachments/assets/21f92a75-ffd9-44dc-a5e5-5daa673a0517" />


