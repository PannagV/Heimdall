import json
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

from flask import Flask, jsonify, render_template, request
from pymongo.errors import PyMongoError

from heimdall.config import ALERT_BUFFER_SIZE, DEFAULT_CONFIG
from heimdall.correlation import CorrelationEngine, IncidentCloser
from heimdall.hces import (
    init_hces_validator,
    parse_eve_line,
    parse_fast_line,
    validate_hces_event,
)
from heimdall.metrics import get_metrics
from heimdall.integrations import JiraSlackIntegration
from heimdall.storage import init_mongo
from heimdall.suricata import list_interfaces, start_suricata, stop_suricata, suricata_running
from heimdall.tailer import LogTailer

app = Flask(__name__, template_folder="template")

alerts: Deque[Dict] = deque(maxlen=ALERT_BUFFER_SIZE)
alert_id = 0
alerts_lock = threading.Lock()

mongo_client: Optional[object] = None
events_collection = None
incidents_collection = None
mongo_lock = threading.Lock()
incidents_lock = threading.Lock()

log_type_lock = threading.Lock()
current_log_type = DEFAULT_CONFIG["suricata_log_type"]

correlation_engine: Optional[CorrelationEngine] = None
incident_closer: Optional[IncidentCloser] = None
integration_client: Optional[JiraSlackIntegration] = None


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


def store_hces_event(event: Dict) -> None:
    global correlation_engine
    if events_collection is None:
        return
    if not validate_hces_event(event):
        return

    correlated = correlation_engine.correlate_event(event) if correlation_engine else event

    try:
        with mongo_lock:
            events_collection.insert_one(correlated)
    except PyMongoError:
        pass


def serialize_doc(doc: Dict) -> Dict:
    if not doc:
        return {}
    doc = dict(doc)
    doc.pop("_id", None)
    return doc


@app.route("/")
def index():
    return render_template(
        "index.html",
        default_config=DEFAULT_CONFIG,
        current_log_type=current_log_type,
    )


@app.route("/api/status")
def status():
    return jsonify({"running": suricata_running(), "log_type": current_log_type})


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
    return jsonify(get_metrics(events_collection, mongo_lock))


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


@app.route("/api/events")
def api_events():
    if events_collection is None:
        return jsonify({"events": []})
    limit = request.args.get("limit", type=int, default=200)
    limit = max(1, min(limit, 1000))
    try:
        with mongo_lock:
            cursor = (
                events_collection.find(
                    {},
                    {
                        "_id": 0,
                        "event_id": 1,
                        "timestamp": 1,
                        "event": 1,
                        "source": 1,
                        "destination": 1,
                        "network": 1,
                        "alert": 1,
                        "incident": 1,
                        "source_type": 1,
                    },
                )
                .sort("timestamp", -1)
                .limit(limit)
            )
            events = list(cursor)
    except PyMongoError:
        events = []
    return jsonify({"events": events})


@app.route("/api/incidents")
def api_incidents():
    if incidents_collection is None:
        return jsonify({"incidents": []})
    limit = request.args.get("limit", type=int, default=200)
    status_filter = request.args.get("status")
    limit = max(1, min(limit, 1000))
    query = {}
    if status_filter:
        query["status"] = status_filter
    try:
        with incidents_lock:
            cursor = (
                incidents_collection.find(query, {"_id": 0})
                .sort("last_seen", -1)
                .limit(limit)
            )
            incidents = list(cursor)
    except PyMongoError:
        incidents = []
    return jsonify({"incidents": incidents})


@app.route("/api/incidents/<incident_id>/close", methods=["POST"])
def api_close_incident(incident_id: str):
    if incidents_collection is None:
        return jsonify({"status": "error", "message": "incidents collection unavailable"}), 503
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        with incidents_lock:
            result = incidents_collection.update_one(
                {"incident_id": incident_id},
                {"$set": {"status": "closed", "last_seen": now_iso}},
            )
            incident = incidents_collection.find_one({"incident_id": incident_id}, {"_id": 0})
        if result.matched_count == 0:
            return jsonify({"status": "error", "message": "incident not found"}), 404
    except PyMongoError:
        return jsonify({"status": "error", "message": "failed to update incident"}), 500

    if integration_client and incident:
        try:
            integration_client.on_incident_updated(incident, "status")
        except Exception:
            pass

    return jsonify({"status": "closed", "incident_id": incident_id})


@app.route("/api/rules", methods=["GET", "PUT"])
def api_rules():
    rules_path = DEFAULT_CONFIG["correlation_rules_path"]
    if request.method == "GET":
        try:
            with open(rules_path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except Exception:
            raw = "[]"
        return jsonify({"path": rules_path, "raw": raw, "rules": correlation_engine.rules if correlation_engine else []})

    payload = request.get_json(silent=True) or {}
    raw = payload.get("raw")
    rules = payload.get("rules")

    if raw is None and rules is None:
        return jsonify({"status": "error", "message": "missing rules payload"}), 400

    if raw is None:
        try:
            raw = json.dumps(rules, indent=2)
        except (TypeError, ValueError):
            return jsonify({"status": "error", "message": "rules must be valid JSON"}), 400

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return jsonify({"status": "error", "message": "invalid JSON"}), 400

    if not isinstance(parsed, list) and not (
        isinstance(parsed, dict) and isinstance(parsed.get("rules"), list)
    ):
        return jsonify({"status": "error", "message": "rules must be a list or {rules: []}"}), 400

    try:
        with open(rules_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(parsed, indent=2))
    except Exception:
        return jsonify({"status": "error", "message": "failed to write rules"}), 500

    if correlation_engine:
        correlation_engine.rules = correlation_engine.load_rules()
    return jsonify({"status": "updated", "path": rules_path})


init_hces_validator()
mongo_client, events_collection, incidents_collection = init_mongo(
    DEFAULT_CONFIG["mongo_uri"]
)
integration_client = JiraSlackIntegration(
    events_collection,
    incidents_collection,
    mongo_lock,
    incidents_lock,
)
correlation_engine = CorrelationEngine(
    mongo_client,
    events_collection,
    incidents_collection,
    mongo_lock,
    incidents_lock,
    DEFAULT_CONFIG["correlation_rules_path"],
    integration_client,
)
incident_closer = IncidentCloser(correlation_engine)
incident_closer.start()

log_dir = DEFAULT_CONFIG["suricata_log_dir"]
tailer = LogTailer(log_dir, current_log_type, parse_eve_line, parse_fast_line, push_alert)
tailer.start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
