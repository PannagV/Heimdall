import os
import socket

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
