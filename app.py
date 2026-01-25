import json
import os
import re
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Optional

from flask import Flask, jsonify, render_template, request
import numpy as np
import pandas as pd
from pymongo import MongoClient
from pymongo.errors import PyMongoError

app = Flask(__name__, template_folder="template")

DEFAULT_CONFIG = {
    "suricata_config": os.environ.get("SURICATA_CONFIG", "/etc/suricata/suricata.yaml"),
    "suricata_iface": os.environ.get("SURICATA_IFACE", "eth0"),
    "suricata_log_dir": os.environ.get("SURICATA_LOG_DIR", "/var/log/suricata"),
    "suricata_log_type": os.environ.get("SURICATA_LOG_TYPE", "eve.json"),
    "mongo_uri": os.environ.get("MONGO_URI", "mongodb://localhost:27017"),
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

ALERTS_VALIDATOR = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [
            "type",
            "timestamp",
            "signature",
            "classification",
            "priority",
            "protocol",
            "src",
            "dst",
            "gid",
            "sid",
            "rev",
        ],
        "properties": {
            "type": {"bsonType": "string"},
            "timestamp": {"bsonType": "string"},
            "signature": {"bsonType": ["string", "null"]},
            "classification": {"bsonType": ["string", "null"]},
            "priority": {"bsonType": ["int", "long", "null"]},
            "protocol": {"bsonType": ["string", "null"]},
            "src": {"bsonType": ["string", "null"]},
            "dst": {"bsonType": ["string", "null"]},
            "gid": {"bsonType": ["int", "long", "null"]},
            "sid": {"bsonType": ["int", "long", "null"]},
            "rev": {"bsonType": ["int", "long", "null"]},
            "ingested_at": {"bsonType": "date"},
            "alert_id": {"bsonType": ["int", "long", "null"]},
        },
        "additionalProperties": True,
    }
}


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


def push_alert(alert: Dict) -> None:
    global alert_id
    with alerts_lock:
        alert_id += 1
        alert["id"] = alert_id
        alerts.append(alert)

    if alert.get("type") == "eve":
        store_eve_alert(alert)


def init_mongo() -> None:
    global mongo_client, mongo_collection

    uri = DEFAULT_CONFIG["mongo_uri"]
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
    except PyMongoError:
        return

    db = client["alerts"]
    existing = list(db.list_collections(filter={"name": "alerts"}))
    if not existing:
        try:
            db.create_collection(
                "alerts",
                validator=ALERTS_VALIDATOR,
                validationLevel="moderate",
            )
        except PyMongoError:
            mongo_client = client
            mongo_collection = db["alerts"]
            return
    else:
        options = existing[0].get("options", {})
        validator = options.get("validator")
        if validator != ALERTS_VALIDATOR:
            pass

    mongo_client = client
    mongo_collection = db["alerts"]


def store_eve_alert(alert: Dict) -> None:
    if mongo_collection is None:
        return

    doc = {
        "type": alert.get("type"),
        "timestamp": alert.get("timestamp"),
        "signature": alert.get("signature"),
        "classification": alert.get("classification"),
        "priority": alert.get("priority"),
        "protocol": alert.get("protocol"),
        "src": alert.get("src"),
        "dst": alert.get("dst"),
        "gid": alert.get("gid"),
        "sid": alert.get("sid"),
        "rev": alert.get("rev"),
        "alert_id": alert.get("id"),
        "ingested_at": datetime.now(timezone.utc),
    }

    try:
        with mongo_lock:
            mongo_collection.insert_one(doc)
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
        return {"raw": line, "type": "fast"}

    data = match.groupdict()
    return {
        "type": "fast",
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


def parse_eve_line(line: str) -> Optional[Dict]:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return {"raw": line, "type": "eve"}

    if data.get("event_type") != "alert":
        return None

    alert = data.get("alert", {})
    return {
        "type": "eve",
        "timestamp": data.get("timestamp"),
        "signature": alert.get("signature"),
        "classification": alert.get("category"),
        "priority": alert.get("severity"),
        "protocol": data.get("proto"),
        "src": f"{data.get('src_ip')}:{data.get('src_port')}" if data.get("src_ip") else None,
        "dst": f"{data.get('dest_ip')}:{data.get('dest_port')}" if data.get("dest_ip") else None,
        "gid": alert.get("gid"),
        "sid": alert.get("signature_id"),
        "rev": alert.get("rev"),
    }


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
    last_24h = now - timedelta(hours=24)

    def aggregate_list(pipeline):
        try:
            with mongo_lock:
                return list(mongo_collection.aggregate(pipeline))
        except PyMongoError:
            return []

    total_count = aggregate_list([{"$count": "count"}])
    last_24h_count = aggregate_list(
        [{"$match": {"ingested_at": {"$gte": last_24h}}}, {"$count": "count"}]
    )
    critical_count = aggregate_list(
        [{"$match": {"priority": 1}}, {"$count": "count"}]
    )

    by_priority = aggregate_list(
        [
            {"$group": {"_id": "$priority", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]
    )
    by_classification = aggregate_list(
        [
            {"$group": {"_id": "$classification", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )
    by_protocol = aggregate_list(
        [
            {"$group": {"_id": "$protocol", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5},
        ]
    )
    top_signatures = aggregate_list(
        [
            {"$group": {"_id": "$signature", "count": {"$sum": 1}}},
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
            {"$match": {"ingested_at": {"$gte": last_24h}}},
            {
                "$project": {
                    "hour": {"$dateTrunc": {"date": "$ingested_at", "unit": "hour"}}
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


log_dir = DEFAULT_CONFIG["suricata_log_dir"]
tailer = LogTailer(log_dir, current_log_type)
tailer.start()

init_mongo()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
