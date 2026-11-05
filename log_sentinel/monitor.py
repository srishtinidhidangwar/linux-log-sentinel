"""Stage 5: live monitoring. Re-runs detection ~1 second after a log file changes."""

from __future__ import annotations

import os
import threading
import time

from . import alerts as A
from .parser import LOG_FILES, parse_log_file

DEBOUNCE_SECONDS = 1.0


def _key(a: dict) -> tuple:
    return (a["type"], a["time"], a["detail"])


def start_monitoring(log_dir: str = "/var/log") -> None:
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        raise SystemExit("watchdog is required for live monitoring: pip install watchdog")

    seen: dict[str, set] = {}
    timers: dict[str, threading.Timer] = {}
    lock = threading.Lock()

    def scan(name: str, announce: bool) -> None:
        path = os.path.join(log_dir, name)
        try:
            df = parse_log_file(path)
        except OSError as exc:
            print(f"[!] Cannot read {path}: {exc.__class__.__name__}")
            return
        with lock:
            known = seen.setdefault(name, set())
            for alert in A.collect_alerts(df):
                if _key(alert) in known:
                    continue
                known.add(_key(alert))
                if announce:
                    print(f"[{time.strftime('%H:%M:%S')}] {alert['severity'].upper():8} "
                          f"{alert['type']}: {alert['detail']}   ({name})", flush=True)

    for name in LOG_FILES:                      # prime: don't replay historical alerts
        if os.path.exists(os.path.join(log_dir, name)):
            scan(name, announce=False)

    class Handler(FileSystemEventHandler):
        def on_modified(self, event):
            name = os.path.basename(event.src_path)
            if event.is_directory or name not in LOG_FILES:
                return
            if name in timers:
                timers[name].cancel()           # debounce bursts of writes
            timers[name] = threading.Timer(DEBOUNCE_SECONDS, scan, args=(name, True))
            timers[name].start()

    observer = Observer()
    observer.schedule(Handler(), log_dir, recursive=False)
    observer.start()
    print(f"[*] Monitoring {log_dir} for {', '.join(LOG_FILES)}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitor.")
    finally:
        observer.stop()
        observer.join()
        for t in timers.values():
            t.cancel()
