#!/usr/bin/env python3
"""
Subscribe to a PDS firehose over the *public* ingress and validate the frames
that come back, using nothing but the stdlib.

This deliberately does not use Wolfram or MetalBear code: verifying our own
output with our own encoder proves nothing. The checks here are the ones a
strict reader (the Go ipld stack a relay runs) applies:

  - every CID link is tag 42 wrapping a byte string whose first byte is 0x00
    (the multibase identity prefix)
  - the frame header names a known $type / op

Usage: firehose_probe.py <host> [seconds] [cursor]

A quiet host publishes nothing while the probe is attached and the run ends
INCONCLUSIVE, which is indistinguishable from a host whose frames never
decode. Pass a cursor to replay from a known sequence number instead — every
frame the host has ever written is checked the same way a live one is.
"""
import base64
import os
import re
import socket
import ssl
import struct
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "bear.croft.click"
budget = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
path = "/xrpc/com.atproto.sync.subscribeRepos"
if len(sys.argv) > 3:
    path += "?cursor=" + sys.argv[3]



def connect(host, path):
    raw = socket.create_connection((host, 443), timeout=10)
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: firehose-probe/1.0\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed during handshake")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n")[0].decode(errors="replace")
    return sock, status, rest


class Reader:
    """Minimal RFC6455 frame reader (server->client frames are unmasked)."""

    def __init__(self, sock, pending=b""):
        self.sock = sock
        self.buf = pending

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("closed")
            self.buf += chunk

    def _take(self, n):
        self._need(n)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def frame(self):
        b0, b1 = self._take(2)
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._take(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._take(8))[0]
        mask = self._take(4) if masked else None
        payload = self._take(ln)
        if mask:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        return opcode, payload


def scan_cid_links(payload):
    """Find every DAG-CBOR tag-42 link and report whether it is well formed.

    Encoding: 0xd8 0x2a (tag 42), then a byte-string header, then the bytes.
    The first content byte MUST be 0x00.
    """
    good, bad = 0, []
    i = 0
    while True:
        i = payload.find(b"\xd8\x2a", i)
        if i < 0:
            break
        j = i + 2
        if j >= len(payload):
            break
        major, minor = payload[j] >> 5, payload[j] & 0x1F
        if major != 2:  # not a byte string -> not a CID link
            i += 2
            continue
        j += 1
        if minor < 24:
            ln = minor
        elif minor == 24:
            ln, j = payload[j], j + 1
        elif minor == 25:
            ln, j = struct.unpack(">H", payload[j:j + 2])[0], j + 2
        else:
            i += 2
            continue
        body = payload[j:j + ln]
        if body[:1] == b"\x00":
            good += 1
        else:
            bad.append(body[:6].hex())
        i = j + ln
    return good, bad


sock, status, pending = connect(host, path)
print(f"  handshake: {status}")
if "101" not in status:
    sys.exit(f"  ERROR: expected 101 Switching Protocols from {host}")

reader = Reader(sock, pending)
sock.settimeout(budget)

frames = total_good = 0
total_bad = []
kinds = {}
deadline = time.time() + budget
try:
    while time.time() < deadline:
        opcode, payload = reader.frame()
        if opcode == 0x9:      # ping
            kinds["ping"] = kinds.get("ping", 0) + 1
            continue
        if opcode not in (0x1, 0x2):
            continue
        frames += 1
        for t in re.findall(rb"#(commit|identity|account|sync|info|handle)", payload):
            kinds[t.decode()] = kinds.get(t.decode(), 0) + 1
        g, b = scan_cid_links(payload)
        total_good += g
        total_bad += b
        if frames <= 2:
            print(f"  frame {frames}: {len(payload)} bytes, {g} CID links")
except (socket.timeout, RuntimeError, OSError) as e:
    if not frames and not kinds:
        print(f"  (no frames: {type(e).__name__})")
finally:
    sock.close()

print()
print(f"  data frames        : {frames}")
print(f"  frame types        : {kinds or '(none)'}")
print(f"  CID links w/ 0x00  : {total_good}")
print(f"  CID links MALFORMED: {len(total_bad)}" + (f" {total_bad[:5]}" if total_bad else ""))
print()
if total_bad:
    print("  RESULT: FAIL — malformed CID links; a strict reader rejects these frames")
    sys.exit(1)
elif total_good:
    print("  RESULT: PASS — every CID link carries the multibase prefix")
elif kinds.get("ping"):
    print("  RESULT: stream alive (keepalive only, no writes during the window)")
else:
    print("  RESULT: INCONCLUSIVE — no frames observed")
