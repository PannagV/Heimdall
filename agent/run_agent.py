#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import requests


DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:5000",
    "shared_secret": "",
    "log_path": "/var/log/suricata/eve.json",
    "log_type": "eve.json",
    "machine_id": "",
    "machine_name": "",
    "machine_group": "",
    "batch_size": 100,
    "flush_interval_seconds": 2,
    "request_timeout_seconds": 10,
    "verify_tls": True,
    "state_file": "~/.heimdall-agent-id",
}


@dataclass
class AgentConfig:
    server_url: str
    shared_secret: str
    log_path: str
    log_type: str
    machine_id: str
    machine_name: str
    machine_group: str
    batch_size: int
    flush_interval_seconds: int
    request_timeout_seconds: int
    verify_tls: bool


class TailReader:
    def __init__(self, path: str) -> None:
        self.path = path
        self.handle = None
        self.inode = None

    def _ensure_open(self) -> bool:
        if not os.path.exists(self.path):
            if self.handle is not None:
                self.handle.close()
                self.handle = None
                self.inode = None
            return False

        try:
            stat = os.stat(self.path)
        except OSError:
            return False

        if self.handle is None or self.inode != stat.st_ino:
            if self.handle is not None:
                self.handle.close()
            self.handle = open(self.path, "r", encoding="utf-8", errors="ignore")
            self.handle.seek(0, os.SEEK_END)
            self.inode = stat.st_ino
        return True

    def poll_line(self) -> Optional[str]:
        if not self._ensure_open():
            return None
        assert self.handle is not None
        line = self.handle.readline()
        if not line:
            return None
        return line.strip()


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_machine_id(configured_id: str, state_file: str) -> str:
    if configured_id:
        return configured_id

    machine_id_file = Path("/etc/machine-id")
    if machine_id_file.exists():
        value = machine_id_file.read_text(encoding="utf-8").strip()
        if value:
            return value

    state_path = Path(os.path.expanduser(state_file))
    if state_path.exists():
        value = state_path.read_text(encoding="utf-8").strip()
        if value:
            return value

    generated = str(uuid.uuid4())
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(generated, encoding="utf-8")
    return generated


def build_agent_config(raw: dict) -> AgentConfig:
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(raw or {})

    server_url = str(cfg["server_url"]).rstrip("/")
    shared_secret = str(cfg["shared_secret"])
    log_path = str(cfg["log_path"])
    log_type = str(cfg["log_type"]).lower()
    if log_type not in {"eve.json", "fast.log"}:
        raise ValueError("log_type must be eve.json or fast.log")

    machine_id = resolve_machine_id(str(cfg.get("machine_id") or ""), str(cfg["state_file"]))
    machine_name = str(cfg.get("machine_name") or "").strip() or socket.gethostname()
    machine_group = str(cfg.get("machine_group") or "").strip()

    batch_size = max(1, min(int(cfg["batch_size"]), 500))
    flush_interval_seconds = max(1, int(cfg["flush_interval_seconds"]))
    request_timeout_seconds = max(1, int(cfg["request_timeout_seconds"]))

    verify_tls = bool(cfg["verify_tls"])

    if not shared_secret:
        raise ValueError("shared_secret is required")

    return AgentConfig(
        server_url=server_url,
        shared_secret=shared_secret,
        log_path=log_path,
        log_type=log_type,
        machine_id=machine_id,
        machine_name=machine_name,
        machine_group=machine_group,
        batch_size=batch_size,
        flush_interval_seconds=flush_interval_seconds,
        request_timeout_seconds=request_timeout_seconds,
        verify_tls=verify_tls,
    )


def sign_payload(secret: str, timestamp: str, nonce: str, body_bytes: bytes) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.{nonce}.".encode("utf-8") + body_bytes,
        hashlib.sha256,
    )
    return digest.hexdigest()


def send_batch(config: AgentConfig, events: List[str]) -> bool:
    payload = {
        "format": config.log_type,
        "machine_group": config.machine_group,
        "events": events,
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    signature = sign_payload(config.shared_secret, timestamp, nonce, body)

    headers = {
        "Content-Type": "application/json",
        "X-Agent-Id": config.machine_id,
        "X-Agent-Name": config.machine_name,
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature,
    }

    url = f"{config.server_url}/api/agent/events"
    try:
        response = requests.post(
            url,
            data=body,
            headers=headers,
            timeout=config.request_timeout_seconds,
            verify=config.verify_tls,
        )
    except requests.RequestException as exc:
        print(f"[agent] send failed: {exc}")
        return False

    if response.status_code >= 300:
        message = response.text.strip()
        if len(message) > 300:
            message = message[:300] + "..."
        print(f"[agent] send rejected ({response.status_code}): {message}")
        return False

    return True


def run(config: AgentConfig) -> None:
    tailer = TailReader(config.log_path)
    pending: List[str] = []
    last_flush = time.time()
    retry_backoff_seconds = 1

    print(f"[agent] starting with machine_id={config.machine_id} machine_name={config.machine_name}")
    print(f"[agent] tailing {config.log_path} as {config.log_type} -> {config.server_url}/api/agent/events")

    while True:
        line = tailer.poll_line()
        if line:
            pending.append(line)

        now = time.time()
        should_flush = bool(pending) and (
            len(pending) >= config.batch_size
            or (now - last_flush) >= config.flush_interval_seconds
        )

        if should_flush:
            snapshot = list(pending)
            ok = send_batch(config, snapshot)
            if ok:
                pending.clear()
                retry_backoff_seconds = 1
                last_flush = now
            else:
                time.sleep(retry_backoff_seconds)
                retry_backoff_seconds = min(retry_backoff_seconds * 2, 30)
                last_flush = time.time()
                continue

        if not line:
            time.sleep(0.2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Heimdall remote ingestion agent")
    parser.add_argument(
        "--config",
        default="agent/config.json",
        help="Path to JSON configuration file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = os.path.abspath(args.config)
    if not os.path.exists(config_path):
        print(f"[agent] config not found: {config_path}")
        return 1

    try:
        raw = load_json(config_path)
        config = build_agent_config(raw)
        run(config)
    except KeyboardInterrupt:
        print("\n[agent] stopped")
        return 0
    except Exception as exc:
        print(f"[agent] fatal error: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
