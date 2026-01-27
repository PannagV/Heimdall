import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request
from jsonschema import Draft7Validator
import numpy as np
import pandas as pd
from pymongo import MongoClient
from pymongo.errors import PyMongoError

app = Flask(__name__, template_folder="template")

DEFAULT_CONFIG = {
    "suricata_config": os.environ.get("SURICATA_CONFIG", "/etc/suricata/suricata.yaml"),
    "suricata_iface": os.environ.get("SURICATA_IFACE", "enp0s3"),
    "suricata_log_dir": os.environ.get("SURICATA_LOG_DIR", "/var/log/suricata"),
    "suricata_log_type": os.environ.get("SURICATA_LOG_TYPE", "eve.json"),
    "mongo_uri": os.environ.get("MONGO_URI", "mongodb://localhost:27017"),
    "sensor_id": os.environ.get("HEIMDALL_SENSOR_ID", "sensor-1"),
    "sensor_hostname": os.environ.get("HEIMDALL_SENSOR_HOSTNAME", socket.gethostname()),
}

ALERT_BUFFER_SIZE = 500

suricata_process: Optional[subprocess.Popen] = None
suricata_lock = threading.Lock()

alerts: Deque[Dict] = deque(maxlen=ALERT_BUFFER_SIZE)
alert_id = 0
alerts_lock = threading.Lock()

mongo_client: Optional[MongoClient] = None
mongo_collection = None
mongo_lock = threading.Lock()

log_type_lock = threading.Lock()
current_log_type = DEFAULT_CONFIG["suricata_log_type"]

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

HCES_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "hces_schema.json")
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
        base["source"] = {k: v for k, v in {"ip": src_ip, "port": src_port}.items() if v is not None}
    if dst_ip or dst_port:
        base["destination"] = {
            k: v for k, v in {"ip": dst_ip, "port": dst_port}.items() if v is not None
        }
    proto = (parsed.get("protocol") or "").lower()
    if proto:
        base["network"] = {"protocol": proto, "transport": proto} if proto in ("tcp", "udp") else {"protocol": proto}

    alert_block = {
        "id": parsed.get("sid"),
        "signature": parsed.get("signature"),
        "category": parsed.get("classification"),
        "severity": parsed.get("priority"),
        "action": "alerted",
    }
    base["alert"] = {k: v for k, v in alert_block.items() if v is not None}
    return base


@dataclass
class TailState:
    path: str
    inode: Optional[int] = None


class LogTailer(threading.Thread):
    def __init__(self, log_dir: str, log_type: str):
        super().__init__(daemon=True)
        self.log_dir = log_dir
        self.log_type = log_type
        self.stop_event = threading.Event()
        self.state = TailState(self._resolve_path())

    def _resolve_path(self) -> str:
        return os.path.join(self.log_dir, self.log_type)

    def set_log_type(self, log_type: str) -> None:
        self.log_type = log_type
        self.state = TailState(self._resolve_path())

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        file_handle = None
        while not self.stop_event.is_set():
            path = self.state.path
            if not os.path.exists(path):
                time.sleep(1)
                continue

            try:
                stat = os.stat(path)
                if self.state.inode != stat.st_ino:
                    if file_handle:
                        file_handle.close()
                    file_handle = open(path, "r", encoding="utf-8", errors="ignore")
                    file_handle.seek(0, os.SEEK_END)
                    self.state.inode = stat.st_ino

                line = file_handle.readline()
                if not line:
                    time.sleep(0.25)
                    continue

                line = line.strip()
                if not line:
                    continue

                if self.log_type == "eve.json":
                    alert = parse_eve_line(line)
                else:
                    alert = parse_fast_line(line)

                if alert:
                    push_alert(alert)
            except Exception:
                time.sleep(0.5)


def push_alert(event: Dict) -> None:
    global alert_id
    is_alert = event.get("event", {}).get("kind") == "alert"
    if is_alert:
        with alerts_lock:
            alert_id += 1
            ui_event = dict(event)
            ui_event["id"] = alert_id
            alerts.append(ui_event)

    store_hces_event(event)


def init_mongo() -> None:
    global mongo_client, mongo_collection

    uri = DEFAULT_CONFIG["mongo_uri"]
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
    except PyMongoError:
        return

    db = client["alerts"]
    existing = list(db.list_collections(filter={"name": "events"}))
    if not existing:
        try:
            db.create_collection(
                "events",
                validator=HCES_MONGO_VALIDATOR,
                validationLevel="moderate",
            )
        except PyMongoError:
            mongo_client = client
            mongo_collection = db["events"]
            return
    else:
        options = existing[0].get("options", {})
        validator = options.get("validator")
        if validator != HCES_MONGO_VALIDATOR:
            try:
                db.command(
                    "collMod",
                    "events",
                    validator=HCES_MONGO_VALIDATOR,
                    validationLevel="moderate",
                )
            except PyMongoError:
                pass

    mongo_client = client
    mongo_collection = db["events"]

    try:
        mongo_collection.create_index("timestamp")
        mongo_collection.create_index("source.ip")
        mongo_collection.create_index("destination.ip")
        mongo_collection.create_index("event.severity")
        mongo_collection.create_index("alert.id")
        mongo_collection.create_index("incident.id")
    except PyMongoError:
        pass


def store_hces_event(event: Dict) -> None:
    if mongo_collection is None:
        return
    if not validate_hces_event(event):
        return

    try:
        with mongo_lock:
            mongo_collection.insert_one(event)
    except PyMongoError:
        pass


def parse_fast_line(line: str) -> Optional[Dict]:
    # Example fast.log line:
    # 01/24/2026-10:10:10.123456  [**] [1:1000001:0] Example alert [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 1.2.3.4:1234 -> 5.6.7.8:80
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


def list_interfaces() -> List[str]:
    try:
        interfaces = [name for name in os.listdir("/sys/class/net") if name != "lo"]
        if not interfaces:
            return ["lo"]
        return sorted(interfaces)
    except Exception:
        return ["lo"]


def build_suricata_command(config_path: str, iface: str) -> list:
    return [
        "suricata",
        "-c",
        config_path,
        "-i",
        iface,
    ]


def start_suricata(config_path: str, iface: str) -> Dict:
    global suricata_process
    with suricata_lock:
        if suricata_process and suricata_process.poll() is None:
            return {"status": "already-running"}

        cmd = build_suricata_command(config_path, iface)
        try:
            suricata_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            return {"status": "error", "message": "suricata not found in PATH"}
        except PermissionError:
            return {"status": "error", "message": "permission denied starting suricata"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    return {"status": "started"}


def stop_suricata() -> Dict:
    global suricata_process
    with suricata_lock:
        if not suricata_process or suricata_process.poll() is not None:
            suricata_process = None
            return {"status": "not-running"}

        try:
            suricata_process.send_signal(signal.SIGTERM)
            suricata_process.wait(timeout=5)
        except Exception:
            suricata_process.kill()
        finally:
            suricata_process = None

    return {"status": "stopped"}


@app.route("/")
def index():
    return render_template(
        "index.html",
        default_config=DEFAULT_CONFIG,
        current_log_type=current_log_type,
    )


@app.route("/api/status")
def status():
    with suricata_lock:
        running = suricata_process is not None and suricata_process.poll() is None
    return jsonify({"running": running, "log_type": current_log_type})


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify({"interfaces": list_interfaces()})


@app.route("/api/start", methods=["POST"])
def api_start():
    payload = request.get_json(silent=True) or {}
    config_path = payload.get("config") or DEFAULT_CONFIG["suricata_config"]
    iface = payload.get("iface") or DEFAULT_CONFIG["suricata_iface"]
    log_type = payload.get("log_type") or DEFAULT_CONFIG["suricata_log_type"]

    if log_type not in ("eve.json", "fast.log"):
        return jsonify({"status": "error", "message": "unsupported log type"}), 400

    with log_type_lock:
        global current_log_type
        current_log_type = log_type
        tailer.set_log_type(log_type)

    result = start_suricata(config_path, iface)
    return jsonify(result)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    result = stop_suricata()
    return jsonify(result)


@app.route("/api/alerts")
def api_alerts():
    since = request.args.get("since", type=int, default=0)
    with alerts_lock:
        new_alerts = [alert for alert in alerts if alert.get("id", 0) > since]
        latest_id = alert_id
    return jsonify({"alerts": new_alerts, "latest_id": latest_id})


@app.route("/api/metrics")
def api_metrics():
    if mongo_collection is None:
        return jsonify(
            {
                "total": 0,
                "last_24h": 0,
                "critical": 0,
                "top_classification": None,
                "by_priority": [],
                "by_classification": [],
                "by_protocol": [],
                "top_signatures": [],
            }
        )

    now = datetime.now(timezone.utc)
    last_24h_iso = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    base_match = {"event.kind": "alert"}

    def aggregate_list(pipeline):
        try:
            with mongo_lock:
                return list(mongo_collection.aggregate(pipeline))
        except PyMongoError:
            return []

    total_count = aggregate_list([{"$match": base_match}, {"$count": "count"}])
    last_24h_count = aggregate_list(
        [
            {"$match": {**base_match, "ingested_at": {"$gte": last_24h_iso}}},
            {"$count": "count"},
        ]
    )
    critical_count = aggregate_list(
        [{"$match": {**base_match, "event.severity": {"$gte": 4}}}, {"$count": "count"}]
    )

    by_priority = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$event.severity", "count": {"$sum": 1}}},
            {"$sort": {"_id": -1}},
        ]
    )
    by_classification = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$alert.category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )
    by_protocol = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$network.protocol", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )
    top_signatures = aggregate_list(
        [
            {"$match": base_match},
            {"$group": {"_id": "$alert.signature", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )

    def format_list(items):
        return [
            {"label": item.get("_id") or "Unknown", "count": item.get("count", 0)}
            for item in items
        ]

    top_class = by_classification[0]["_id"] if by_classification else None

    hourly = aggregate_list(
        [
            {"$match": {**base_match, "ingested_at": {"$gte": last_24h_iso}}},
            {
                "$project": {
                    "hour": {
                        "$dateTrunc": {
                            "date": {"$dateFromString": {"dateString": "$ingested_at"}},
                            "unit": "hour",
                        }
                    }
                }
            },
            {"$group": {"_id": "$hour", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]
    )

    hourly_series = []
    avg_per_hour = 0.0
    if hourly:
        df = pd.DataFrame(hourly)
        df = df.rename(columns={"_id": "hour"})
        df["hour"] = pd.to_datetime(df["hour"])
        df = df.set_index("hour").asfreq("H", fill_value=0)
        counts = df["count"].to_numpy(dtype=int)
        labels = [ts.strftime("%H:%M") for ts in df.index]
        hourly_series = [
            {"label": label, "count": int(count)}
            for label, count in zip(labels, counts)
        ]
        avg_per_hour = float(np.mean(counts)) if counts.size else 0.0

    return jsonify(
        {
            "total": total_count[0]["count"] if total_count else 0,
            "last_24h": last_24h_count[0]["count"] if last_24h_count else 0,
            "critical": critical_count[0]["count"] if critical_count else 0,
            "top_classification": top_class,
            "by_priority": format_list(by_priority),
            "by_classification": format_list(by_classification),
            "by_protocol": format_list(by_protocol),
            "top_signatures": format_list(top_signatures),
            "hourly_counts": hourly_series,
            "avg_per_hour": avg_per_hour,
        }
    )


@app.route("/api/clear", methods=["POST"])
def api_clear():
    global alert_id
    with alerts_lock:
        alerts.clear()
        alert_id = 0
    return jsonify({"status": "cleared"})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


init_hces_validator()
init_mongo()

log_dir = DEFAULT_CONFIG["suricata_log_dir"]
tailer = LogTailer(log_dir, current_log_type)
tailer.start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
