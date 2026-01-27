# Project Heimdall

Heimdall is a Linux-based SIEM that ingests Suricata logs and stores them as normalized documents using the Heimdall Common Event Schema (HCES).

## What changed

- Added production-grade HCES normalization for Suricata EVE JSON and fast.log events.
- Preserved raw events for audit and replay under `raw_event`.
- Enforced schema validation before MongoDB insertion.
- Added MongoDB indexes for high-volume search and incident workflows.

## HCES overview

HCES guarantees a source-agnostic, write-optimized structure with clear separation between detection and network context. Every document includes:

- Base fields: `event_id`, `timestamp`, `ingested_at`, `event`, `source_type`, `sensor`
- Optional context: `source`, `destination`, `network`, `alert`, `user`, `file`, `incident`, `attack`, `threat`
- Raw event preservation: `raw_event`

The schema definition lives in [hces_schema.json](hces_schema.json).

## Suricata mapping highlights

- `event.kind` is `alert` for Suricata `alert` events, otherwise `event`.
- `event.category` is `intrusion` + `network` for alerts, `network` for other events.
- `event.severity` uses a normalized 1–5 scale (Suricata 1 → 5, 2 → 3, 3 → 1).
- `alert.id` maps from Suricata `signature_id`.
- Network context uses generic `source`, `destination`, and `network` blocks.
- Raw EVE JSON is stored unchanged in `raw_event.data`.

## MongoDB storage

Events are stored in the `alerts.events` collection with schema validation enabled. Required indexes:

- `timestamp`
- `source.ip`
- `destination.ip`
- `event.severity`
- `alert.id`
- `incident.id`

## Environment variables

- `SURICATA_CONFIG` (default: `/etc/suricata/suricata.yaml`)
- `SURICATA_IFACE` (default: `eth0`)
- `SURICATA_LOG_DIR` (default: `/var/log/suricata`)
- `SURICATA_LOG_TYPE` (default: `eve.json`)
- `MONGO_URI` (default: `mongodb://localhost:27017`)
- `HEIMDALL_SENSOR_ID` (default: `sensor-1`)
- `HEIMDALL_SENSOR_HOSTNAME` (default: system hostname)

## Notes for future sources

HCES is source-agnostic by design. New log sources should map into the same top-level structure without schema redesign, and must preserve original payloads in `raw_event`.
