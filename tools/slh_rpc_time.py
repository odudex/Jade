#!/usr/bin/env python3
"""Time the sign_slh_dsa RPC using the device's own log timestamps.

The logging build interleaves text with CBOR on the same USB CDC, which no CBOR
reader can follow -- but the log lines carry millisecond timestamps, so the
device reports its own handler time: from the request arriving on the wire to
'Success' after slh_sign() returns. That figure includes the CBOR parse and the
progress-bar redraws, which the on-device benchmark deliberately excludes.
"""
import re
import sys
import time

import cbor2 as cbor
import serial

sys.path.insert(0, "/media/odudex/Projects/other_esp_projects/Jade/Jade")
from jadepy.jade import JadeInterface

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
ITERS = int(sys.argv[2]) if len(sys.argv) > 2 else 3
STANDARD = (sys.argv[3] if len(sys.argv) > 3 else "standard") == "standard"

ser = serial.Serial(PORT, 115200, timeout=0.5)
RX = re.compile(r"I \((\d+)\) wire\.c:.*from 2")
OK = re.compile(r"I \((\d+)\) sign_slh_dsa\.c: \d+: Success")


def send(method, params=None):
    req = JadeInterface.build_request(str(int(time.time() * 1000) % 1000000), method, params)
    ser.write(cbor.dumps(req))
    ser.flush()


def pump(seconds):
    end = time.time() + seconds
    text = ""
    while time.time() < end:
        data = ser.read(4096)
        if data:
            text += data.decode("utf-8", errors="replace")
    return text


send("get_version_info")
pump(3)
send("debug_set_mnemonic", {
    "mnemonic": "all all all all all all all all all all all all",
    "temporary_wallet": True,
})
pump(4)
print(f"sign_slh_dsa, {'SLH-DSA-SHA2-128s' if STANDARD else 'custom-slh-dsa'}, {ITERS} iterations",
      flush=True)

handler, wall = [], []
for i in range(ITERS):
    t0 = time.perf_counter()
    send("sign_slh_dsa", {
        "path": [44, 0, 0],
        "message": i.to_bytes(32, "big"),
        "is_standard": STANDARD,
    })
    text = pump(40 if STANDARD else 40)
    dt = time.perf_counter() - t0
    rx = RX.findall(text)
    ok = OK.findall(text)
    if rx and ok:
        ms = int(ok[-1]) - int(rx[0])
        handler.append(ms)
        wall.append(dt)
        print(f"  {i + 1:3d}  device handler {ms:6d} ms", flush=True)
    else:
        print(f"  {i + 1:3d}  no match (rx={len(rx)} ok={len(ok)})", flush=True)

if handler:
    print(f"\n  handler  min {min(handler)} ms  mean {sum(handler) // len(handler)} ms  "
          f"max {max(handler)} ms  spread {max(handler) - min(handler)} ms", flush=True)
ser.close()
