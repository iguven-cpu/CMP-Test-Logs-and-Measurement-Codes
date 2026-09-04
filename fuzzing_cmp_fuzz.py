#!/usr/bin/env python3
"""
CMP Web-Interface Black-Box Fuzzer (anonymized)
===============================================
Targets the firmware's server-side input-validation pipeline by POSTing
malformed values DIRECTLY to the web-management configuration endpoints,
bypassing the browser-side JavaScript validation. This exercises the firmware
validation (the paper's "input validation / reduced attack surface" claim),
not the client-side JS.

Captured request format (reverse-engineered from the live device):
    POST /<page>.mwp
    Content-Type: application/x-www-form-urlencoded; charset=UTF-8
    Cookie: <httpOnly session cookie>
    Body: <FieldName>=<value>&pageMode=bufferwrite&_=<nonce><counter>

  * Field naming pattern:  Cmp<Page><Field>_1  (e.g. CmpServerAddr_1)
  * pageMode=bufferwrite   VALIDATES and stages the value; the server returns
                           {"resp":"OK"} if accepted or {"resp":"ERROR","msg":..}
                           if rejected. A separate pageMode=flush is required to
                           COMMIT the staged buffer. This fuzzer sends only
                           bufferwrite, so malformed values are validated by the
                           firmware but never persisted -- a built-in safety net.
  * _  = anti-replay token = session nonce followed by an incrementing suffix.

SAFETY
------
This mutates live device configuration. Run ONLY with:
  * "config save" disabled on the device (reboot restores), or a test unit
  * a serial console / syslog open to observe the native trace + logbook
  * the built-in ping crash-oracle running (thread below)
The script restores each fuzzed field to its baseline after every request.

USAGE
-----
1. Log in to the device web interface in a browser.
2. DevTools (F12) -> Application -> Cookies -> copy the session cookie
   name=value (httpOnly is fine, DevTools still shows it).
3. DevTools -> Console -> read the anti-replay nonce global -> copy the value.
4. Provide configuration via environment variables, then run:
       python cmp_fuzz.py
Results are written to results/fuzz_<timestamp>.jsonl and a summary CSV.

Environment variables:
   CMP_DEVICE   device address or host           (e.g. 192.0.2.10)
   CMP_COOKIE   "name=value" session cookie
   CMP_NONCE    anti-replay session nonce
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --------------------------------------------------------------------------
# Configuration (supply via environment variables)
# --------------------------------------------------------------------------
HOST = os.environ.get("CMP_DEVICE", "192.0.2.10")           # placeholder address
BASE = f"https://{HOST}"
SESSION_COOKIE = os.environ.get("CMP_COOKIE", "PASTE_name=value_HERE")
NONCE = os.environ.get("CMP_NONCE", "PASTE_NONCE_HERE")     # anti-replay session nonce

REQUEST_TIMEOUT = 6.0      # seconds; a timeout is a strong anomaly signal
DELAY_BETWEEN = 0.4        # rate limit between requests (be gentle)
PING_EVERY = 1             # ping the device before every N requests (crash oracle)
STOP_ON_DOWN = True        # halt fuzzing if the device stops responding to ping

# Endpoint + target-field map. Each field is fuzzed independently and then
# restored to its (generic placeholder) baseline. Field names follow the
# confirmed Cmp<Page><Field>_1 naming pattern. Baselines are non-sensitive
# placeholders; replace with values valid for your test unit.
TARGETS = [
    # (endpoint,             field_name,               baseline_value)
    ("cmp_server.mwp",     "CmpServerAddr_1",         "192.0.2.20"),
    ("cmp_server.mwp",     "CmpServerPort_1",         "6443"),
    ("cmp_server.mwp",     "CmpServerCertPath_1",     "cmp"),
    ("cmp_server.mwp",     "CmpServerRevokePath_1",   ""),
    ("cmp_clientauth.mwp", "CmpClientAuthRef_1",      "testref"),
    ("cmp_clientauth.mwp", "CmpClientAuthSecret_1",   "testsecret"),
    ("cmp_certenroll.mwp", "CmpCertEnrollSubject_1",
     "/CN=test-client/OU=For testing purposes only/O=Example/C=XX"),
]

# --------------------------------------------------------------------------
# Payload corpus (negative / malformed inputs)
# --------------------------------------------------------------------------
def build_payloads() -> list[tuple[str, str]]:
    """Return (category, payload) pairs."""
    p: list[tuple[str, str]] = []

    # Command / shell injection
    for s in ["10.0.0.1;reboot", "$(reboot)", "`id`", "| cat /etc/passwd",
              "&& ls", "; shutdown -h now", "\n reboot"]:
        p.append(("cmd_injection", s))

    # Path traversal
    for s in ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
              "/etc/shadow", "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd"]:
        p.append(("path_traversal", s))

    # Format strings
    for s in ["%s%s%s%s%s", "%n%n%n", "%x%x%x%x", "%99999999s"]:
        p.append(("format_string", s))

    # Buffer / length (bounds around MAX_LEN)
    for n in [256, 1024, 4096, 16384, 65535]:
        p.append((f"long_{n}", "A" * n))

    # Numeric boundary (esp. for Port)
    for s in ["-1", "0", "65536", "99999999999", "0x1bb", "8080e2", "  6443  ", "6443\x00"]:
        p.append(("numeric_boundary", s))

    # NUL / control / non-UTF8 / unicode
    for s in ["A\x00B", "\x00", "\r\n\r\n", "\x1b[31m",
              "\u0000\ufeff", "𝔘𝔫𝔦𝔠𝔬𝔡𝔢", "test\u202eevil"]:
        p.append(("control_unicode", s))

    # DN / structural (relevant for Subject)
    for s in ["/CN=" + "A" * 2000, "/CN=a\x00/O=x", "CN=;rm -rf /",
              "/CN=<script>alert(1)</script>", "/" + "OU=x/" * 500]:
        p.append(("dn_structural", s))

    # Empty / whitespace
    for s in ["", " ", "\t", "   \n   "]:
        p.append(("empty_whitespace", s))

    return p


# --------------------------------------------------------------------------
# Crash oracle (ping) + result model
# --------------------------------------------------------------------------
_device_down = threading.Event()


def ping_once(host: str) -> bool:
    flag = "-n" if os.name == "nt" else "-c"
    try:
        r = subprocess.run(["ping", flag, "1", "-w", "1000", host],
                           capture_output=True, text=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def ping_monitor(host: str, stop: threading.Event):
    """Background thread: continuous liveness log; sets _device_down on loss."""
    while not stop.is_set():
        up = ping_once(host)
        ts = datetime.now().strftime("%H:%M:%S")
        if up:
            _device_down.clear()
            print(f"\033[92m[{ts}] PING UP\033[0m", flush=True)
        else:
            _device_down.set()
            print(f"\033[91m[{ts}] PING >>> DOWN <<<\033[0m", flush=True)
        stop.wait(1.0)


@dataclass
class Result:
    ts: str
    endpoint: str
    field: str
    category: str
    payload_repr: str
    payload_len: int
    status: int | None
    resp_len: int | None
    elapsed_ms: float | None
    anomaly: str
    device_up: bool


# --------------------------------------------------------------------------
# Core fuzzing
# --------------------------------------------------------------------------
def token() -> str:
    return f"{NONCE}{int(time.time() * 1000) % 10_000_000}"


def submit(sess: requests.Session, endpoint: str, field: str, value: str):
    """POST one field value; return (status, resp_len, elapsed_ms, error)."""
    url = f"{BASE}/{endpoint}"
    data = {field: value, "pageMode": "bufferwrite", "_": token()}
    t0 = time.perf_counter()
    try:
        r = sess.post(url, data=data, timeout=REQUEST_TIMEOUT, verify=False)
        dt = (time.perf_counter() - t0) * 1000
        return r.status_code, len(r.content), dt, None
    except requests.exceptions.Timeout:
        return None, None, REQUEST_TIMEOUT * 1000, "timeout"
    except requests.exceptions.RequestException as e:
        return None, None, (time.perf_counter() - t0) * 1000, f"conn_error:{type(e).__name__}"


def classify(status, resp_len, err) -> str:
    if err:
        return err                      # timeout / connection error -> likely crash/hang
    if status is None:
        return "no_response"
    if status >= 500:
        return f"http_{status}"
    if status == 0:
        return "http_0"
    return ""                            # no anomaly (2xx/3xx/4xx handled by device)


def run():
    if "PASTE" in SESSION_COOKIE or "PASTE" in NONCE:
        print("ERROR: set CMP_COOKIE and CMP_NONCE (and CMP_DEVICE). See header for how to obtain them.")
        sys.exit(1)

    out_dir = Path(__file__).parent / "fuzzing_results"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl = out_dir / f"fuzz_{stamp}.jsonl"
    csv_path = out_dir / f"fuzz_{stamp}.csv"

    sess = requests.Session()
    name, _, val = SESSION_COOKIE.partition("=")
    sess.cookies.set(name.strip(), val.strip(), domain=HOST)
    sess.headers.update({
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
    })

    payloads = build_payloads()
    stop = threading.Event()
    mon = threading.Thread(target=ping_monitor, args=(HOST, stop), daemon=True)
    mon.start()
    time.sleep(1.2)  # let the oracle establish a baseline

    total = len(TARGETS) * len(payloads)
    print(f"Fuzzing {len(TARGETS)} fields x {len(payloads)} payloads = {total} requests\n")

    anomalies = 0
    done = 0
    with jsonl.open("w", encoding="utf-8") as jf, csv_path.open("w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=[f.name for f in Result.__dataclass_fields__.values()])
        writer.writeheader()

        for endpoint, field, baseline in TARGETS:
            for category, payload in payloads:
                if STOP_ON_DOWN and _device_down.is_set():
                    print("\n\033[91mDevice DOWN -- halting fuzzing. Investigate the last payload.\033[0m")
                    stop.set()
                    _summary(anomalies, done, jsonl, csv_path)
                    return

                if done % PING_EVERY == 0:
                    up_before = not _device_down.is_set()
                else:
                    up_before = True

                status, resp_len, dt, err = submit(sess, endpoint, field, payload)
                anomaly = classify(status, resp_len, err)

                res = Result(
                    ts=datetime.now().isoformat(timespec="seconds"),
                    endpoint=endpoint, field=field, category=category,
                    payload_repr=repr(payload)[:80], payload_len=len(payload),
                    status=status, resp_len=resp_len,
                    elapsed_ms=round(dt, 1) if dt is not None else None,
                    anomaly=anomaly, device_up=up_before,
                )
                jf.write(json.dumps(asdict(res), ensure_ascii=False) + "\n")
                jf.flush()
                writer.writerow(asdict(res))

                if anomaly:
                    anomalies += 1
                    print(f"\033[93m[!] ANOMALY {endpoint} {field} <- {res.payload_repr} "
                          f"=> {anomaly} (status={status}, {res.elapsed_ms}ms)\033[0m")

                # restore baseline so the next payload starts clean
                submit(sess, endpoint, field, baseline)
                done += 1
                time.sleep(DELAY_BETWEEN)

            # final restore for the field
            submit(sess, endpoint, field, baseline)

    stop.set()
    _summary(anomalies, done, jsonl, csv_path)


def _summary(anomalies: int, done: int, jsonl: Path, csv_path: Path):
    print(f"\nDone: {done} requests sent, {anomalies} anomalies.")
    print(f"  JSONL: {jsonl}")
    print(f"  CSV:   {csv_path}")


if __name__ == "__main__":
    run()
