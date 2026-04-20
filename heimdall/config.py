import os
import socket
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None


def _load_env() -> None:
    if load_dotenv is None:
        return
    here = Path(__file__).resolve()
    candidates = [here.parent / ".env", here.parent.parent / ".env"]
    for candidate in candidates:
        if candidate.exists():
            load_dotenv(candidate, override=False)
    load_dotenv(override=False)


_load_env()

DEFAULT_CONFIG = {
    "suricata_config": os.environ.get("SURICATA_CONFIG", "/etc/suricata/suricata.yaml"),
    "suricata_iface": os.environ.get("SURICATA_IFACE", "enp0s3"),
    "suricata_log_dir": os.environ.get("SURICATA_LOG_DIR", "/var/log/suricata"),
    "suricata_log_type": os.environ.get("SURICATA_LOG_TYPE", "eve.json"),
    "mongo_uri": os.environ.get("MONGO_URI", "mongodb://localhost:27017"),
    "sensor_id": os.environ.get("HEIMDALL_SENSOR_ID", "sensor-1"),
    "sensor_hostname": os.environ.get("HEIMDALL_SENSOR_HOSTNAME", socket.gethostname()),
    "incident_timeout_minutes": int(os.environ.get("INCIDENT_TIMEOUT_MINUTES", "120")),
    "correlation_rules_path": os.environ.get(
        "CORRELATION_RULES_PATH",
        os.path.join(os.path.dirname(__file__), "..", "correlation_rules.json"),
    ),
    "jwt_secret": os.environ.get("JWT_SECRET", ""),
    "refresh_token_secret": os.environ.get("REFRESH_TOKEN_SECRET", ""),
    "jwt_issuer": os.environ.get("JWT_ISSUER", "heimdall"),
    "access_token_minutes": int(os.environ.get("ACCESS_TOKEN_MINUTES", "15")),
    "refresh_token_days": int(os.environ.get("REFRESH_TOKEN_DAYS", "10")),
    "auth_rate_limit_per_min": int(os.environ.get("AUTH_RATE_LIMIT_PER_MIN", "8")),
    "auth_refresh_rate_limit_per_min": int(os.environ.get("AUTH_REFRESH_RATE_LIMIT_PER_MIN", "12")),
    "agent_shared_secret": os.environ.get("AGENT_SHARED_SECRET", ""),
    "agent_max_batch_size": int(os.environ.get("AGENT_MAX_BATCH_SIZE", "200")),
    "agent_max_clock_skew_seconds": int(os.environ.get("AGENT_MAX_CLOCK_SKEW_SECONDS", "300")),
    "agent_nonce_ttl_seconds": int(os.environ.get("AGENT_NONCE_TTL_SECONDS", "900")),
    "agent_rate_limit_per_min": int(os.environ.get("AGENT_RATE_LIMIT_PER_MIN", "120")),
    "bootstrap_admin_user": os.environ.get("BOOTSTRAP_ADMIN_USER", ""),
    "bootstrap_admin_password": os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", ""),
    "bootstrap_admin_role": os.environ.get("BOOTSTRAP_ADMIN_ROLE", "admin"),
    "jira_base_url": os.environ.get("JIRA_BASE_URL", ""),
    "jira_project_key": os.environ.get("JIRA_PROJECT_KEY", "HEIMDALL"),
    "jira_email": os.environ.get("JIRA_EMAIL", ""),
    "jira_api_token": os.environ.get("JIRA_API_TOKEN", ""),
    "jira_issue_type": os.environ.get("JIRA_ISSUE_TYPE", "Security Incident"),
    "jira_field_heimdall_id": os.environ.get("JIRA_FIELD_HEIMDALL_ID", ""),
    "jira_field_source_ips": os.environ.get("JIRA_FIELD_SOURCE_IPS", ""),
    "jira_field_event_count": os.environ.get("JIRA_FIELD_EVENT_COUNT", ""),
    "slack_webhook_url": os.environ.get("SLACK_WEBHOOK_URL", ""),
    "slack_channel": os.environ.get("SLACK_CHANNEL", ""),
    "integration_min_priority": os.environ.get("INTEGRATION_MIN_PRIORITY", "medium"),
}

ALERT_BUFFER_SIZE = 500
