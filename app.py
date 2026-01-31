import json
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

from flask import Flask, jsonify, render_template, request, g, send_from_directory
from pymongo.errors import PyMongoError

from heimdall.auth import (
    create_access_token,
    get_user_by_refresh,
    hash_password,
    is_role_allowed,
    issue_tokens,
    log_auth_event,
    store_refresh_token,
    validate_jwt,
    verify_password,
    hash_refresh_token,
    rotate_refresh_token,
    utc_iso,
)
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
users_collection = None
refresh_tokens_collection = None
audit_collection = None
mongo_lock = threading.Lock()
incidents_lock = threading.Lock()

log_type_lock = threading.Lock()
current_log_type = DEFAULT_CONFIG["suricata_log_type"]

correlation_engine: Optional[CorrelationEngine] = None
incident_closer: Optional[IncidentCloser] = None

auth_lock = threading.Lock()
auth_rate_limits: Dict[str, Dict] = {}


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


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(key: str, limit: int) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    with auth_lock:
        entry = auth_rate_limits.get(key)
        if not entry or entry["reset"] <= now:
            auth_rate_limits[key] = {"count": 1, "reset": now + 60}
            return True
        if entry["count"] >= limit:
            return False
        entry["count"] += 1
        return True


def require_auth(required_role: Optional[str] = None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            token = auth_header.replace("Bearer ", "").strip()
            if not token:
                return jsonify({"status": "error", "message": "missing token"}), 401
            payload = validate_jwt(token)
            if not payload:
                return jsonify({"status": "error", "message": "invalid token"}), 401
            g.user_id = payload.get("sub")
            g.role = payload.get("role")
            if required_role and not is_role_allowed(g.role, required_role):
                return jsonify({"status": "error", "message": "forbidden"}), 403
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator


@app.before_request
def enforce_api_auth():
    path = request.path
    if not path.startswith("/api/"):
        return None
    if path.startswith("/api/auth/"):
        return None
    return require_auth()(lambda: None)()


@app.route("/")
def index():
    return render_template(
        "index.html",
        default_config=DEFAULT_CONFIG,
        current_log_type=current_log_type,
    )


@app.route("/icon.png")
def favicon():
    return send_from_directory(app.root_path, "icon.png")


@app.route("/hsoclogo.png")
def hsoc_logo():
    return send_from_directory(app.root_path, "hsoclogo.png")


@app.route("/api/status")
@require_auth("viewer")
def status():
    return jsonify({"running": suricata_running(), "log_type": current_log_type})


@app.route("/api/interfaces")
@require_auth("viewer")
def api_interfaces():
    return jsonify({"interfaces": list_interfaces()})


@app.route("/api/start", methods=["POST"])
@require_auth("admin")
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
@require_auth("admin")
def api_stop():
    result = stop_suricata()
    return jsonify(result)


@app.route("/api/alerts")
@require_auth("viewer")
def api_alerts():
    since = request.args.get("since", type=int, default=0)
    with alerts_lock:
        new_alerts = [alert for alert in alerts if alert.get("id", 0) > since]
        latest_id = alert_id
    return jsonify({"alerts": new_alerts, "latest_id": latest_id})


@app.route("/api/metrics")
@require_auth("viewer")
def api_metrics():
    return jsonify(get_metrics(events_collection, mongo_lock))


@app.route("/api/clear", methods=["POST"])
@require_auth("analyst")
def api_clear():
    global alert_id
    with alerts_lock:
        alerts.clear()
        alert_id = 0
    return jsonify({"status": "cleared"})


@app.route("/api/health")
@require_auth("viewer")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    if users_collection is None or refresh_tokens_collection is None:
        return jsonify({"status": "error", "message": "auth unavailable"}), 503
    if not DEFAULT_CONFIG["jwt_secret"] or not DEFAULT_CONFIG["refresh_token_secret"]:
        return jsonify({"status": "error", "message": "auth secrets not configured"}), 500

    if not rate_limit(f"login:{client_ip()}", DEFAULT_CONFIG["auth_rate_limit_per_min"]):
        return jsonify({"status": "error", "message": "rate limit"}), 429

    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if not username or not password:
        return jsonify({"status": "error", "message": "invalid credentials"}), 400

    user = users_collection.find_one({"$or": [{"username": username}, {"email": username}]})
    if not user or not verify_password(password, user.get("password_hash", "")):
        log_auth_event(audit_collection, user.get("user_id") if user else None, "login", False, client_ip())
        return jsonify({"status": "error", "message": "invalid credentials"}), 401

    tokens = issue_tokens(user["user_id"], user["role"])
    store_refresh_token(refresh_tokens_collection, user["user_id"], tokens.refresh_token)
    log_auth_event(audit_collection, user.get("user_id"), "login", True, client_ip())

    return jsonify(
        {"access_token": tokens.access_token, "refresh_token": tokens.refresh_token}
    )


@app.route("/api/auth/refresh", methods=["POST"])
def api_refresh():
    if users_collection is None or refresh_tokens_collection is None:
        return jsonify({"status": "error", "message": "auth unavailable"}), 503
    if not DEFAULT_CONFIG["jwt_secret"] or not DEFAULT_CONFIG["refresh_token_secret"]:
        return jsonify({"status": "error", "message": "auth secrets not configured"}), 500

    if not rate_limit(
        f"refresh:{client_ip()}", DEFAULT_CONFIG["auth_refresh_rate_limit_per_min"]
    ):
        return jsonify({"status": "error", "message": "rate limit"}), 429

    payload = request.get_json(silent=True) or {}
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        return jsonify({"status": "error", "message": "missing refresh token"}), 400

    user = get_user_by_refresh(refresh_tokens_collection, users_collection, refresh_token)
    if not user:
        log_auth_event(audit_collection, None, "refresh", False, client_ip())
        return jsonify({"status": "error", "message": "invalid refresh token"}), 401

    old_hash = hash_refresh_token(refresh_token)
    new_refresh = rotate_refresh_token(refresh_tokens_collection, old_hash)
    store_refresh_token(refresh_tokens_collection, user["user_id"], new_refresh)
    refresh_tokens_collection.update_one(
        {"token_hash": old_hash}, {"$set": {"last_used_at": utc_iso()}}
    )

    access = create_access_token(user["user_id"], user["role"])
    log_auth_event(audit_collection, user.get("user_id"), "refresh", True, client_ip())

    return jsonify({"access_token": access, "refresh_token": new_refresh})


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    if refresh_tokens_collection is None:
        return jsonify({"status": "error", "message": "auth unavailable"}), 503
    payload = request.get_json(silent=True) or {}
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        return jsonify({"status": "error", "message": "missing refresh token"}), 400

    token_hash = hash_refresh_token(refresh_token)
    refresh_tokens_collection.update_one(
        {"token_hash": token_hash}, {"$set": {"revoked": True, "revoked_at": utc_iso()}}
    )
    log_auth_event(audit_collection, None, "logout", True, client_ip())
    return jsonify({"status": "ok"})


@app.route("/api/auth/me")
@require_auth("viewer")
def api_me():
    return jsonify({"user_id": g.user_id, "role": g.role})


@app.route("/api/auth/users", methods=["POST"])
@require_auth("admin")
def api_create_user():
    if users_collection is None:
        return jsonify({"status": "error", "message": "auth unavailable"}), 503
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    role = (payload.get("role") or "viewer").lower()
    email = (payload.get("email") or "").strip() or None

    if role not in ("viewer", "analyst", "admin"):
        return jsonify({"status": "error", "message": "invalid role"}), 400
    if not username or not password:
        return jsonify({"status": "error", "message": "username and password required"}), 400

    user_doc = {
        "user_id": str(uuid.uuid4()),
        "username": username,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "created_at": utc_iso(),
    }
    try:
        users_collection.insert_one(user_doc)
    except PyMongoError:
        return jsonify({"status": "error", "message": "user exists"}), 409

    log_auth_event(audit_collection, user_doc["user_id"], "create_user", True, client_ip())
    return jsonify({"status": "created", "user_id": user_doc["user_id"]})


@app.route("/api/events")
@require_auth("viewer")
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
@require_auth("viewer")
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
@require_auth("analyst")
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
@require_auth("admin")
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
(
    mongo_client,
    events_collection,
    incidents_collection,
    users_collection,
    refresh_tokens_collection,
    audit_collection,
) = init_mongo(DEFAULT_CONFIG["mongo_uri"])

if (
    users_collection is not None
    and DEFAULT_CONFIG["bootstrap_admin_user"]
    and DEFAULT_CONFIG["bootstrap_admin_password"]
):
    existing = users_collection.find_one({"username": DEFAULT_CONFIG["bootstrap_admin_user"]})
    if not existing:
        users_collection.insert_one(
            {
                "user_id": str(uuid.uuid4()),
                "username": DEFAULT_CONFIG["bootstrap_admin_user"],
                "password_hash": hash_password(DEFAULT_CONFIG["bootstrap_admin_password"]),
                "role": DEFAULT_CONFIG["bootstrap_admin_role"],
                "created_at": utc_iso(),
            }
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
