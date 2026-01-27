import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    from jsonschema import Draft7Validator
except ImportError:  # pragma: no cover - optional dependency
    Draft7Validator = None  # type: ignore[assignment]

from .config import DEFAULT_CONFIG

HCES_MONGO_VALIDATOR = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [
            "event_id",
            "timestamp",
            "ingested_at",
            "event",
            "source_type",
            "sensor",
            "raw_event",
        ],
        "properties": {
            "event_id": {"bsonType": "string"},
            "timestamp": {"bsonType": "string"},
            "ingested_at": {"bsonType": "string"},
            "event": {
                "bsonType": "object",
                "required": ["kind", "category", "type", "severity", "outcome"],
                "properties": {
                    "kind": {"bsonType": "string"},
                    "category": {"bsonType": "array"},
                    "type": {"bsonType": "array"},
                    "severity": {"bsonType": "int"},
                    "outcome": {"bsonType": "string"},
                },
            },
            "source_type": {"bsonType": "string"},
            "sensor": {
                "bsonType": "object",
                "required": ["id", "type", "hostname"],
                "properties": {
                    "id": {"bsonType": "string"},
                    "type": {"bsonType": "string"},
                    "hostname": {"bsonType": "string"},
                },
            },
            "source": {"bsonType": "object"},
            "destination": {"bsonType": "object"},
            "network": {"bsonType": "object"},
            "alert": {"bsonType": "object"},
            "incident": {"bsonType": "object"},
            "raw_event": {
                "bsonType": "object",
                "required": ["source", "data"],
                "properties": {
                    "source": {"bsonType": "string"},
                    "data": {},
                },
            },
        },
        "additionalProperties": True,
    }
}

HCES_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "hces_schema.json")
HCES_SCHEMA: Dict = {}
HCES_VALIDATOR: Optional[Draft7Validator] = None


def load_hces_schema() -> Dict:
    try:
        with open(HCES_SCHEMA_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {
            "type": "object",
            "required": [
                "event_id",
                "timestamp",
                "ingested_at",
                "event",
                "source_type",
                "sensor",
                "raw_event",
            ],
            "properties": {
                "event_id": {"type": "string"},
                "timestamp": {"type": "string"},
                "ingested_at": {"type": "string"},
                "event": {"type": "object"},
                "source_type": {"type": "string"},
                "sensor": {"type": "object"},
                "raw_event": {"type": "object"},
            },
            "additionalProperties": True,
        }


def init_hces_validator() -> None:
    global HCES_SCHEMA, HCES_VALIDATOR
    HCES_SCHEMA = load_hces_schema()
    if Draft7Validator is None:
        HCES_VALIDATOR = None
        return
    try:
        HCES_VALIDATOR = Draft7Validator(HCES_SCHEMA)
    except Exception:
        HCES_VALIDATOR = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_iso_timestamp(timestamp: Optional[str]) -> Optional[str]:
    if not timestamp:
        return None
    ts = timestamp.strip()
    if ts.endswith("Z"):
        ts = ts.replace("Z", "+00:00")
    tz_match = re.search(r"([+-]\d{2})(\d{2})$", ts)
    if tz_match:
        ts = ts[: tz_match.start()] + tz_match.group(1) + ":" + tz_match.group(2)
    try:
        parsed = datetime.fromisoformat(ts)
        parsed_utc = parsed.astimezone(timezone.utc)
        return parsed_utc.isoformat().replace("+00:00", "Z")
    except Exception:
        pass

    for fmt in ("%m/%d/%Y-%H:%M:%S.%f", "%m/%d/%Y-%H:%M:%S"):
        try:
            parsed = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            return parsed.isoformat().replace("+00:00", "Z")
        except Exception:
            continue

    return timestamp


def parse_ip_port(value: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    if not value:
        return None, None
    if value.startswith("[") and "]" in value:
        host, _, port_str = value.rpartition(":")
        host = host.strip("[]")
        if port_str.isdigit():
            return host, int(port_str)
        return value, None
    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        if port_str.isdigit():
            return host, int(port_str)
    return value, None


def normalize_severity(suricata_severity: Optional[int]) -> int:
    if suricata_severity == 1:
        return 5
    if suricata_severity == 2:
        return 3
    if suricata_severity == 3:
        return 1
    return 3


def coerce_int(value: object) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def build_sensor_context() -> Dict:
    return {
        "id": DEFAULT_CONFIG["sensor_id"],
        "type": "ids",
        "hostname": DEFAULT_CONFIG["sensor_hostname"],
    }


def build_network_context(data: Dict) -> Dict:
    source_ip = data.get("src_ip")
    dest_ip = data.get("dest_ip")
    source_port = coerce_int(data.get("src_port"))
    dest_port = coerce_int(data.get("dest_port"))
    source_mac = data.get("src_mac")
    dest_mac = data.get("dest_mac")

    network: Dict[str, object] = {}

    protocol = (data.get("app_proto") or data.get("proto") or "").lower()
    if protocol:
        network["protocol"] = protocol

    if protocol in ("tcp", "udp"):
        network["transport"] = protocol

    direction_map = {
        "to_server": "inbound",
        "to_client": "outbound",
    }
    direction = direction_map.get(data.get("direction"))
    if direction:
        network["direction"] = direction

    flow = data.get("flow") or {}
    bytes_total = None
    packets_total = None
    if isinstance(flow, dict):
        bytes_server = flow.get("bytes_toserver")
        bytes_client = flow.get("bytes_toclient")
        if isinstance(bytes_server, int) and isinstance(bytes_client, int):
            bytes_total = bytes_server + bytes_client
        packets_server = flow.get("pkts_toserver")
        packets_client = flow.get("pkts_toclient")
        if isinstance(packets_server, int) and isinstance(packets_client, int):
            packets_total = packets_server + packets_client

    if isinstance(bytes_total, int):
        network["bytes"] = bytes_total
    if isinstance(packets_total, int):
        network["packets"] = packets_total

    source = None
    if source_ip or source_port or source_mac:
        source = {"ip": source_ip, "port": source_port, "mac": source_mac}
        source = {k: v for k, v in source.items() if v is not None}

    destination = None
    if dest_ip or dest_port or dest_mac:
        destination = {"ip": dest_ip, "port": dest_port, "mac": dest_mac}
        destination = {k: v for k, v in destination.items() if v is not None}

    context: Dict[str, object] = {}
    if source:
        context["source"] = source
    if destination:
        context["destination"] = destination
    if network:
        context["network"] = network
    return context


def validate_hces_event(event: Dict) -> bool:
    if HCES_VALIDATOR is None:
        return True
    errors = sorted(HCES_VALIDATOR.iter_errors(event), key=lambda err: err.path)
    return not errors


def build_hces_base(
    *,
    timestamp: Optional[str],
    kind: str,
    category: List[str],
    event_type: List[str],
    severity: int,
    outcome: str,
    raw_data: object,
) -> Dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": normalize_iso_timestamp(timestamp) or utc_now_iso(),
        "ingested_at": utc_now_iso(),
        "event": {
            "kind": kind,
            "category": category,
            "type": event_type,
            "severity": severity,
            "outcome": outcome,
        },
        "source_type": "suricata",
        "sensor": build_sensor_context(),
        "raw_event": {
            "source": "suricata",
            "data": raw_data,
        },
    }


def build_hces_event_from_eve(data: Dict, raw_line: str) -> Dict:
    event_type = data.get("event_type")
    is_alert = event_type == "alert"
    alert = data.get("alert") or {}
    base = build_hces_base(
        timestamp=data.get("timestamp"),
        kind="alert" if is_alert else "event",
        category=["intrusion", "network"] if is_alert else ["network"],
        event_type=["ids"],
        severity=normalize_severity(alert.get("severity") if is_alert else None),
        outcome="unknown",
        raw_data=data,
    )

    context = build_network_context(data)
    base.update(context)

    if is_alert:
        alert_block = {
            "id": alert.get("signature_id"),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "severity": alert.get("severity"),
            "action": alert.get("action") or "alerted",
        }
        base["alert"] = {k: v for k, v in alert_block.items() if v is not None}

    fileinfo = data.get("fileinfo") or {}
    if isinstance(fileinfo, dict) and fileinfo:
        file_block = {
            "name": fileinfo.get("filename"),
            "mime_type": fileinfo.get("mimetype"),
            "hash": {"sha256": fileinfo.get("sha256")},
        }
        base["file"] = {
            k: v for k, v in file_block.items() if v is not None and v != {}
        }

    return base


def build_hces_event_from_fast(parsed: Dict, raw_line: str) -> Dict:
    src_ip, src_port = parse_ip_port(parsed.get("src"))
    dst_ip, dst_port = parse_ip_port(parsed.get("dst"))
    base = build_hces_base(
        timestamp=parsed.get("timestamp"),
        kind="alert",
        category=["intrusion", "network"],
        event_type=["ids"],
        severity=normalize_severity(parsed.get("priority")),
        outcome="unknown",
        raw_data=raw_line,
    )
    if src_ip or src_port:
        base["source"] = {
            k: v for k, v in {"ip": src_ip, "port": src_port}.items() if v is not None
        }
    if dst_ip or dst_port:
        base["destination"] = {
            k: v for k, v in {"ip": dst_ip, "port": dst_port}.items() if v is not None
        }
    proto = (parsed.get("protocol") or "").lower()
    if proto:
        base["network"] = (
            {"protocol": proto, "transport": proto}
            if proto in ("tcp", "udp")
            else {"protocol": proto}
        )

    alert_block = {
        "id": parsed.get("sid"),
        "signature": parsed.get("signature"),
        "category": parsed.get("classification"),
        "severity": parsed.get("priority"),
        "action": "alerted",
    }
    base["alert"] = {k: v for k, v in alert_block.items() if v is not None}
    return base


def parse_fast_line(line: str) -> Optional[Dict]:
    pattern = re.compile(
        r"^(?P<ts>\S+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+\[Classification:\s+(?P<classification>.*?)\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<proto>\w+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)$"
    )
    match = pattern.match(line)
    if not match:
        return build_hces_base(
            timestamp=utc_now_iso(),
            kind="event",
            category=["network"],
            event_type=["ids"],
            severity=3,
            outcome="unknown",
            raw_data=line,
        )

    data = match.groupdict()
    parsed = {
        "timestamp": data.get("ts"),
        "signature": data.get("msg"),
        "classification": data.get("classification"),
        "priority": int(data.get("priority")) if data.get("priority") else None,
        "protocol": data.get("proto"),
        "src": data.get("src"),
        "dst": data.get("dst"),
        "gid": int(data.get("gid")) if data.get("gid") else None,
        "sid": int(data.get("sid")) if data.get("sid") else None,
        "rev": int(data.get("rev")) if data.get("rev") else None,
    }
    return build_hces_event_from_fast(parsed, line)


def parse_eve_line(line: str) -> Optional[Dict]:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return build_hces_base(
            timestamp=utc_now_iso(),
            kind="event",
            category=["network"],
            event_type=["ids"],
            severity=3,
            outcome="unknown",
            raw_data=line,
        )

    return build_hces_event_from_eve(data, line)
