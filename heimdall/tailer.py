import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class TailState:
    path: str
    inode: Optional[int] = None


class LogTailer(threading.Thread):
    def __init__(
        self,
        log_dir: str,
        log_type: str,
        parse_eve: Callable[[str], Optional[dict]],
        parse_fast: Callable[[str], Optional[dict]],
        on_event: Callable[[dict], None],
    ) -> None:
        super().__init__(daemon=True)
        self.log_dir = log_dir
        self.log_type = log_type
        self.parse_eve = parse_eve
        self.parse_fast = parse_fast
        self.on_event = on_event
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
                    event = self.parse_eve(line)
                else:
                    event = self.parse_fast(line)

                if event:
                    self.on_event(event)
            except Exception:
                time.sleep(0.5)
