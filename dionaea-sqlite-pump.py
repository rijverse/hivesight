#!/usr/bin/env python3
"""
dionaea-sqlite-pump: tail dionaea.sqlite -> append to dionaea.json

Dionaea's `log_json` ihandler fails to subscribe to incidents on this image
(the C-level subscription appears broken — `LogJsonHandler ready!` is logged
but no `accepted connection` events ever fire, and `dionaea.json` never grows).

The `log_sqlite` ihandler IS working and writes connection records to
/var/lib/dionaea/dionaea.sqlite. This sidecar polls that SQLite database,
formats new rows as JSON lines, and appends them to
/var/log/dionaea/dionaea.json — which promtail is configured to ship to Loki.

Schema reference (from dionaea sources):
  connections: connection, connection_type, connection_transport,
               connection_protocol, connection_timestamp, connection_root,
               connection_parent, local_host, local_port, remote_host,
               remote_hostname, remote_port
"""

import os
import json
import sqlite3
import time
import signal
import sys
from datetime import datetime, timezone

SQLITE_PATH = os.environ.get("DIONAEA_SQLITE", "/opt/dionaea/var/lib/dionaea/dionaea.sqlite")
# Write to /opt/dionaea/var/log/dionaea.json (NOT .../dionaea/dionaea.json) because
# the dionaea-logs docker volume is mounted at /var/log/dionaea in the promtail
# container, so promtail reads /var/log/dionaea/dionaea.json. Dionaea itself
# writes its own files under var/log/dionaea/ (a subdir), but we want our JSON
# output at the volume root so promtail picks it up.
JSON_OUT    = os.environ.get("DIONAEA_JSON",  "/opt/dionaea/var/log/dionaea.json")
POLL_SECS   = float(os.environ.get("DIONAEA_PUMP_POLL", "1.0"))
# last_seen survives restarts here so rows inserted while the pump was down
# aren't skipped. Lives on the same (writable) log volume as JSON_OUT.
STATE_PATH  = os.environ.get("DIONAEA_PUMP_STATE", "/opt/dionaea/var/log/.dionaea-pump-state.json")
# Rotate dionaea.json once it exceeds this; promtail follows the new inode.
# One .1 generation is kept, so disk use is bounded at ~2x this value.
MAX_JSON_BYTES = int(os.environ.get("DIONAEA_PUMP_MAX_BYTES", str(128 * 1024 * 1024)))

_running = True

def _stop(signum, frame):
    global _running
    _running = False

signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)

def ts_to_iso(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None

def load_last_seen():
    """Return the persisted last-seen connection id, or None on first run."""
    try:
        with open(STATE_PATH) as f:
            return int(json.load(f)["last_seen"])
    except Exception:
        return None

def save_last_seen(value):
    tmp = STATE_PATH + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"last_seen": value}, f)
        os.replace(tmp, STATE_PATH)
    except OSError as e:
        print(f"[dionaea-pump] could not persist state: {e}", flush=True)

def maybe_rotate():
    try:
        if os.path.getsize(JSON_OUT) > MAX_JSON_BYTES:
            os.replace(JSON_OUT, JSON_OUT + ".1")
            print(f"[dionaea-pump] rotated {JSON_OUT}", flush=True)
    except OSError:
        pass

def main():
    # Initialise the JSON file (preserve any existing content)
    if not os.path.exists(JSON_OUT):
        open(JSON_OUT, "a").close()

    print(f"[dionaea-pump] sqlite={SQLITE_PATH} json={JSON_OUT} poll={POLL_SECS}s", flush=True)

    last_seen = load_last_seen()
    if last_seen is not None:
        print(f"[dionaea-pump] resuming from connection id={last_seen}", flush=True)
    while _running:
        try:
            conn = sqlite3.connect(SQLITE_PATH, timeout=2.0)
            cur = conn.cursor()
            # First run ever: start from current max id so a pre-existing db
            # isn't backfilled wholesale. Restarts resume from saved state.
            if last_seen is None:
                cur.execute("SELECT MAX(connection) FROM connections")
                row = cur.fetchone()
                last_seen = row[0] or 0
                save_last_seen(last_seen)
                print(f"[dionaea-pump] starting from connection id={last_seen}", flush=True)
            cur.execute(
                """
                SELECT connection, connection_type, connection_transport,
                       connection_protocol, connection_timestamp,
                       local_host, local_port, remote_host,
                       remote_hostname, remote_port
                FROM connections
                WHERE connection > ?
                ORDER BY connection ASC
                """,
                (last_seen,),
            )
            rows = cur.fetchall()
            conn.close()
        except sqlite3.OperationalError as e:
            # dionaea holds a write lock on the db sometimes; just retry
            print(f"[dionaea-pump] sqlite busy: {e}", flush=True)
            time.sleep(POLL_SECS)
            continue
        except Exception as e:
            print(f"[dionaea-pump] sqlite error: {e}", flush=True)
            time.sleep(POLL_SECS)
            continue

        if not rows:
            time.sleep(POLL_SECS)
            continue

        maybe_rotate()
        with open(JSON_OUT, "a", buffering=1) as f:
            for r in rows:
                conn_id, conn_type, conn_transport, conn_protocol, \
                    conn_ts, local_host, local_port, remote_host, \
                    remote_hostname, remote_port = r
                evt = {
                    "eventid": f"dionaea.connection.{conn_type}",
                    # Match log_json ihandler schema: "connection" is a dict
                    # with protocol/transport/type, not an int id. The
                    # orchestrator's handle_dionaea() reads conn.get("protocol").
                    "connection": {
                        "protocol": conn_protocol,
                        "transport": conn_transport,
                        "type": conn_type,
                    },
                    "connection_id": conn_id,
                    "connection_type": conn_type,
                    "connection_transport": conn_transport,
                    "connection_protocol": conn_protocol,
                    "connection_timestamp": ts_to_iso(conn_ts),
                    "local_host": local_host,
                    "local_port": local_port,
                    "remote_host": remote_host,
                    "remote_hostname": remote_hostname or "",
                    "remote_port": remote_port,
                    "src_ip": remote_host,
                    "src_port": remote_port,
                    "dst_ip": local_host,
                    "dst_port": local_port,
                    "protocol": conn_protocol,
                    "timestamp": ts_to_iso(conn_ts),
                }
                f.write(json.dumps(evt) + "\n")
                if conn_id > last_seen:
                    last_seen = conn_id
        save_last_seen(last_seen)

        time.sleep(POLL_SECS)

    print("[dionaea-pump] exiting", flush=True)

if __name__ == "__main__":
    main()
