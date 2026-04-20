# Heimdall Event Query Language

This document describes the SQL-like query language used by the Events search bar and the API endpoint:

- `GET /api/events/search?q=...`

The language is designed for safe filtering of Heimdall Common Event Schema (HCES) documents in the `events` collection.

## Quick start

Short-form query:

```sql
severity >= 4 AND source.ip = "10.10.5.7" ORDER BY timestamp DESC LIMIT 100
```

Full SQL-like form:

```sql
SELECT timestamp, alert.signature, source.ip
FROM events
WHERE severity >= 4 AND kind = "alert"
ORDER BY timestamp DESC
LIMIT 100
OFFSET 0
```

## Syntax

### Statements

- Short form:
  - `[WHERE-expression] [ORDER BY ...] [LIMIT n] [OFFSET n]`
- SQL-like form:
  - `SELECT <field-list|*> FROM events [WHERE ...] [ORDER BY ...] [LIMIT n] [OFFSET n]`

### Operators

- Comparisons: `=`, `!=`, `>`, `>=`, `<`, `<=`
- Logic: `AND`, `OR`, `NOT`, parentheses
- Text: `LIKE` (supports `%` and `_`, case-insensitive)
- Set: `IN (v1, v2, ...)`
- Null checks: `IS NULL`, `IS NOT NULL`
- Array membership: `CONTAINS`

## Supported fields

Core event:

- `timestamp`
- `event_id`
- `source_type`
- `kind` (alias of `event.kind`)
- `severity` (alias of `event.severity`)
- `outcome` (alias of `event.outcome`)
- `category` (alias of `event.category`, array)
- `type` (alias of `event.type`, array)

Source and destination:

- `source.ip` (alias `src_ip`)
- `source.port` (alias `src_port`)
- `destination.ip` (alias `dst_ip`)
- `destination.port` (alias `dst_port`)

Network:

- `network.protocol` (alias `protocol`)
- `network.transport` (alias `transport`)

Alert:

- `alert.id`
- `alert.signature` (alias `signature`)
- `alert.category`
- `alert.severity`

Incident:

- `incident.id`
- `incident.incident_id` (alias `incident_id`)

## Literals and values

- Strings may be quoted with single or double quotes.
- Bare words are allowed for string values (for example: `kind = alert`).
- Integer fields require integer values.
- `NULL` can only be used with `IS NULL` and `IS NOT NULL`.

## Examples

```sql
kind = alert AND severity >= 3 ORDER BY timestamp DESC LIMIT 200
```

```sql
source.ip = "192.168.1.10" AND destination.port IN (22, 3389)
```

```sql
signature LIKE "%ET TROJAN%" AND timestamp >= "2026-04-20T00:00:00Z"
```

```sql
category CONTAINS intrusion AND protocol = tcp
```

```sql
SELECT timestamp, severity, signature, src_ip
FROM events
WHERE severity >= 3
ORDER BY timestamp DESC
LIMIT 50
```

## API response shape

Success (`200`):

```json
{
  "events": [...],
  "query_meta": {
    "query": "...",
    "limit": 200,
    "offset": 0,
    "sort": [{ "field": "timestamp", "direction": "desc" }],
    "selected_fields": []
  }
}
```

Validation error (`400`):

```json
{
  "status": "error",
  "message": "Unknown field 'foo'",
  "position": 12
}
```

## Current constraints

- Only `FROM events` is supported.
- No joins or subqueries.
- Limits are bounded server-side.
- Unsupported field/operator combinations are rejected.
