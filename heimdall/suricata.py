import os
import signal
import subprocess
import threading
from typing import Dict, List, Optional

suricata_process: Optional[subprocess.Popen] = None
suricata_lock = threading.Lock()


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


def suricata_running() -> bool:
    with suricata_lock:
        return suricata_process is not None and suricata_process.poll() is None
