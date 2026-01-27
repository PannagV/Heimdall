import threading
from collections import deque
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


init_hces_validator()
mongo_client, events_collection, incidents_collection = init_mongo(
    DEFAULT_CONFIG["mongo_uri"]
)
correlation_engine = CorrelationEngine(
    mongo_client,
    events_collection,
    incidents_collection,
    mongo_lock,
    incidents_lock,
    DEFAULT_CONFIG["correlation_rules_path"],
)
incident_closer = IncidentCloser(correlation_engine)
incident_closer.start()

log_dir = DEFAULT_CONFIG["suricata_log_dir"]
tailer = LogTailer(log_dir, current_log_type, parse_eve_line, parse_fast_line, push_alert)
tailer.start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
