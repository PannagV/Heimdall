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
}

ALERT_BUFFER_SIZE = 500
