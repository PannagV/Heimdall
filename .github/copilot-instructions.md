# Heimdall AI agent guide

## Big picture architecture
- Flask app in [app.py](app.py) serves the UI (templates/static) and JSON APIs; it also boots all background threads.
- Suricata ingestion is file-based: [heimdall/tailer.py](heimdall/tailer.py) tails eve.json or fast.log and pushes parsed events into `push_alert()` in [app.py](app.py).
- Normalization to HCES happens in [heimdall/hces.py](heimdall/hces.py); raw payloads are preserved under `raw_event.data` (see schema in [hces_schema.json](hces_schema.json)).
- MongoDB storage and schema validation are centralized in [heimdall/storage.py](heimdall/storage.py); collections live in the `alerts` DB and include `events`, `incidents`, `users`, `refresh_tokens`, `audit_logs`.
- Correlation is rule-driven: [heimdall/correlation.py](heimdall/correlation.py) loads [correlation_rules.json](correlation_rules.json) and attaches `incident` info to alert events, plus manages the `incidents` collection.
- Optional integrations live in [heimdall/integrations.py](heimdall/integrations.py) (Jira + Slack) and are invoked async from the correlation engine.

## Data flow & key patterns
- Ingestion path: Suricata log line → `parse_eve_line()`/`parse_fast_line()` → HCES event → `CorrelationEngine.correlate_event()` → Mongo insert.
- Alerts are also buffered in-memory for the live monitor UI via `alerts` deque in [app.py](app.py).
- Incident auto-closure is handled by `IncidentCloser` thread based on `INCIDENT_TIMEOUT_MINUTES` in [heimdall/config.py](heimdall/config.py).
- Auth uses JWT access tokens + refresh tokens stored in MongoDB; see [heimdall/auth.py](heimdall/auth.py) and `/api/auth/*` routes in [app.py](app.py).

## Developer workflows (discoverable)
- Install deps: `pip install -r requirements.txt` (see [requirements.txt](requirements.txt)).
- Run the server: `python app.py` (Flask debug server; see `__main__` in [app.py](app.py)).
- Optional `.env` support is loaded from repo root or package dir via [heimdall/config.py](heimdall/config.py).

## Project-specific conventions
- HCES normalization always sets `event.kind`, `event.category`, `event.type`, and `event.severity` and preserves raw source data; extend in [heimdall/hces.py](heimdall/hces.py).
- Mongo validators are updated via `collMod` on startup; keep schema changes in [heimdall/hces.py](heimdall/hces.py) and [heimdall/correlation.py](heimdall/correlation.py) consistent.
- Correlation rules accept either a JSON list or `{ "rules": [] }` when edited through `/api/rules` (see [app.py](app.py)).

## Integration points
- Suricata process control is shell-based (`suricata` in PATH) in [heimdall/suricata.py](heimdall/suricata.py).
- Jira/Slack integration uses env-driven config and minimum priority gating (see [heimdall/integrations.py](heimdall/integrations.py) and [heimdall/config.py](heimdall/config.py)).
- Metrics endpoints depend on pandas/numpy aggregation over Mongo data (see [heimdall/metrics.py](heimdall/metrics.py)).
