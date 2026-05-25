import json
import hashlib
import hmac
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

from flask import Flask, Response, jsonify, render_template, request, g, send_from_directory, stream_with_context
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
from heimdall.copilot import CopilotError, COPILOT_EVENT_PROJECTION, analyze_copilot
from heimdall.hces import (
    init_hces_validator,
    parse_eve_line,
    parse_fast_line,
    validate_hces_event,
)
from heimdall.event_query import QuerySyntaxError, parse_event_search_query
from heimdall.metrics import get_metrics
from heimdall.integrations import JiraSlackIntegration
from heimdall.storage import init_mongo
from heimdall.suricata import list_interfaces, start_suricata, stop_suricata, suricata_running
from heimdall.tailer import LogTailer

app = Flask(__name__, template_folder="template")

alerts: Deque[Dict] = deque(maxlen=ALERT_BUFFER_SIZE)
alert_id = 0
alerts_lock = threading.Lock()
alerts_condition = threading.Condition(alerts_lock)

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
agent_nonce_lock = threading.Lock()
agent_nonces: Dict[str, float] = {}


def push_alert(event: Dict) -> None:
    global alert_id
    is_alert = event.get("event", {}).get("kind") == "alert" or bool(event.get("alert"))
    if is_alert:
        with alerts_lock:
            alert_id += 1
            ui_event = dict(event)
            ui_event["id"] = alert_id
            alerts.append(ui_event)
            alerts_condition.notify_all()

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


def apply_machine_identity(
    event: Dict,
    machine_id: str,
    machine_name: str,
    machine_group: Optional[str] = None,
) -> Dict:
    machine = {
        "id": machine_id,
        "name": machine_name,
    }
    if machine_group:
        machine["group"] = machine_group
    event["machine"] = machine

    sensor = event.get("sensor") if isinstance(event.get("sensor"), dict) else {}
    sensor["id"] = machine_id
    sensor["hostname"] = machine_name
    sensor.setdefault("type", "ids")
    event["sensor"] = sensor
    return event


def _cleanup_agent_nonces(now_ts: float, ttl_seconds: int) -> None:
    stale = [key for key, seen_at in agent_nonces.items() if now_ts - seen_at > ttl_seconds]
    for key in stale:
        agent_nonces.pop(key, None)


def verify_agent_request(raw_body: bytes):
    secret = (DEFAULT_CONFIG.get("agent_shared_secret") or "").strip()
    if not secret:
        return None, (jsonify({"status": "error", "message": "agent ingestion is not configured"}), 503)

    machine_id = (request.headers.get("X-Agent-Id") or "").strip()
    machine_name = (request.headers.get("X-Agent-Name") or "").strip()
    timestamp_raw = (request.headers.get("X-Agent-Timestamp") or "").strip()
    nonce = (request.headers.get("X-Agent-Nonce") or "").strip()
    signature = (request.headers.get("X-Agent-Signature") or "").strip().lower()

    if not machine_id or not machine_name:
        return None, (jsonify({"status": "error", "message": "missing machine identity headers"}), 401)
    if not timestamp_raw or not nonce or not signature:
        return None, (jsonify({"status": "error", "message": "missing agent auth headers"}), 401)

    if not rate_limit(f"agent:{machine_id}", DEFAULT_CONFIG["agent_rate_limit_per_min"]):
        return None, (jsonify({"status": "error", "message": "rate limit"}), 429)

    try:
        timestamp = int(timestamp_raw)
    except ValueError:
        return None, (jsonify({"status": "error", "message": "invalid timestamp"}), 401)

    now_ts = int(time.time())
    max_skew = max(30, int(DEFAULT_CONFIG["agent_max_clock_skew_seconds"]))
    if abs(now_ts - timestamp) > max_skew:
        return None, (jsonify({"status": "error", "message": "timestamp skew too large"}), 401)

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp_raw}.{nonce}.".encode("utf-8") + raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None, (jsonify({"status": "error", "message": "invalid signature"}), 401)

    nonce_ttl = max(60, int(DEFAULT_CONFIG["agent_nonce_ttl_seconds"]))
    nonce_key = f"{machine_id}:{nonce}"
    with agent_nonce_lock:
        _cleanup_agent_nonces(float(now_ts), nonce_ttl)
        if nonce_key in agent_nonces:
            return None, (jsonify({"status": "error", "message": "replay detected"}), 409)
        agent_nonces[nonce_key] = float(now_ts)

    return {"machine_id": machine_id, "machine_name": machine_name}, None


def require_auth(required_role: Optional[str] = None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            token = auth_header.replace("Bearer ", "").strip()
            if not token:
                token = (request.args.get("token") or "").strip()
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
    if path.startswith("/api/agent/"):
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


@app.route("/api/alerts/stream")
@require_auth("viewer")
def api_alerts_stream():
    since = request.args.get("since", type=int, default=0)
    last_event_id = request.headers.get("Last-Event-ID")
    if last_event_id and last_event_id.isdigit():
        since = max(since, int(last_event_id))

    @stream_with_context
    def generate():
        last_id = since
        last_ping = time.time()
        while True:
            new_alerts = []
            with alerts_lock:
                if last_id < alert_id:
                    new_alerts = [alert for alert in alerts if alert.get("id", 0) > last_id]

            if new_alerts:
                for alert in new_alerts:
                    last_id = max(last_id, alert.get("id", 0))
                    payload = json.dumps(alert, default=str)
                    yield f"id: {last_id}\ndata: {payload}\n\n"
                continue

            with alerts_condition:
                alerts_condition.wait(timeout=1.0)

            if time.time() - last_ping >= 10:
                yield ": ping\n\n"
                last_ping = time.time()

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
                        "machine": 1,
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


@app.route("/api/agent/events", methods=["POST"])
def api_agent_events():
    if events_collection is None:
        return jsonify({"status": "error", "message": "events collection unavailable"}), 503

    raw_body = request.get_data(cache=True, as_text=False)
    identity, auth_error = verify_agent_request(raw_body)
    if auth_error:
        return auth_error

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "invalid JSON payload"}), 400

    log_format = (payload.get("format") or "").strip().lower()
    if log_format not in ("eve.json", "fast.log"):
        return jsonify({"status": "error", "message": "format must be eve.json or fast.log"}), 400

    events_payload = payload.get("events")
    if isinstance(events_payload, str):
        events_payload = [events_payload]
    if not isinstance(events_payload, list) or not events_payload:
        return jsonify({"status": "error", "message": "events must be a non-empty array"}), 400

    max_batch_size = max(1, min(int(DEFAULT_CONFIG["agent_max_batch_size"]), 1000))
    if len(events_payload) > max_batch_size:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"batch too large (max {max_batch_size})",
                }
            ),
            413,
        )

    machine_group = payload.get("machine_group")
    if machine_group is not None:
        machine_group = str(machine_group).strip() or None

    parser = parse_eve_line if log_format == "eve.json" else parse_fast_line
    accepted = 0
    rejected = 0

    for item in events_payload:
        if isinstance(item, dict):
            raw_line = str(item.get("line") or "")
        elif isinstance(item, str):
            raw_line = item
        else:
            rejected += 1
            continue

        line = raw_line.strip()
        if not line:
            rejected += 1
            continue

        parsed = parser(line)
        if not parsed:
            rejected += 1
            continue

        apply_machine_identity(
            parsed,
            identity["machine_id"],
            identity["machine_name"],
            machine_group,
        )
        push_alert(parsed)
        accepted += 1

    return jsonify(
        {
            "status": "ok",
            "machine": {
                "id": identity["machine_id"],
                "name": identity["machine_name"],
                "group": machine_group,
            },
            "format": log_format,
            "accepted": accepted,
            "rejected": rejected,
        }
    )


@app.route("/api/events/search")
@require_auth("viewer")
def api_events_search():
    if events_collection is None:
        return jsonify({"events": [], "query_meta": {"query": ""}})

    query = (request.args.get("q") or "").strip()
    default_limit = request.args.get("limit", type=int, default=200)
    default_limit = max(1, min(default_limit, 1000))

    if len(query) > 4000:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "query is too long",
                    "position": 4000,
                }
            ),
            400,
        )

    try:
        parsed = parse_event_search_query(
            query,
            default_limit=default_limit,
            max_limit=1000,
        )
    except QuerySyntaxError as exc:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": exc.message,
                    "position": exc.position,
                }
            ),
            400,
        )

    try:
        with mongo_lock:
            cursor = (
                events_collection.find(parsed.mongo_filter, parsed.projection)
                .sort(parsed.sort)
                .skip(parsed.offset)
                .limit(parsed.limit)
            )
            events = list(cursor)
    except PyMongoError:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "failed to execute query",
                }
            ),
            500,
        )

    query_meta = {
        "query": query,
        "limit": parsed.limit,
        "offset": parsed.offset,
        "sort": [
            {
                "field": field,
                "direction": "desc" if direction < 0 else "asc",
            }
            for field, direction in parsed.sort
        ],
        "selected_fields": parsed.selected_fields,
    }

    return jsonify({"events": events, "query_meta": query_meta})


@app.route("/api/copilot/analyze", methods=["POST"])
@require_auth("analyst")
def api_copilot_analyze():
    if events_collection is None:
        return jsonify({"status": "error", "message": "events collection unavailable"}), 503

    if not rate_limit(f"copilot:{g.user_id}", DEFAULT_CONFIG["copilot_rate_limit_per_min"]):
        return jsonify({"status": "error", "message": "rate limit"}), 429

    payload = request.get_json(silent=True) or {}
    event_ids = payload.get("event_ids")
    if isinstance(event_ids, str):
        event_ids = [event_ids]
    if not isinstance(event_ids, list):
        return jsonify({"status": "error", "message": "event_ids must be an array"}), 400

    cleaned_ids = []
    for item in event_ids:
        if item is None:
            continue
        value = str(item).strip()
        if value:
            cleaned_ids.append(value)

    if not cleaned_ids:
        return jsonify({"status": "error", "message": "event_ids cannot be empty"}), 400

    try:
        with mongo_lock:
            cursor = events_collection.find(
                {"event_id": {"$in": cleaned_ids}},
                COPILOT_EVENT_PROJECTION,
            )
            events = list(cursor)
    except PyMongoError:
        return jsonify({"status": "error", "message": "failed to load events"}), 500

    event_map = {event.get("event_id"): event for event in events if event.get("event_id")}
    missing = [event_id for event_id in cleaned_ids if event_id not in event_map]
    if missing:
        preview = missing[:5]
        suffix = "..." if len(missing) > 5 else ""
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"events not found: {', '.join(preview)}{suffix}",
                    "missing": preview,
                }
            ),
            404,
        )

    ordered = [event_map[event_id] for event_id in cleaned_ids]

    try:
        result = analyze_copilot(ordered, cleaned_ids, DEFAULT_CONFIG)
    except CopilotError as exc:
        return jsonify({"status": "error", "message": exc.message}), exc.status_code
    except Exception:
        return jsonify({"status": "error", "message": "copilot analysis failed"}), 500

    return jsonify({"status": "ok", "result": result})


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
integration_client.bootstrap()
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
