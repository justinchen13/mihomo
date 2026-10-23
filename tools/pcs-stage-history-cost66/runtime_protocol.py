#!/usr/bin/env python3
"""Isolated CLI/runtime acceptance, derived from protocol-probe.py.

All credentials, certificates, destinations and traffic are disposable fixtures.
The outside runner uses --network none and publishes no host ports. The inside
probe joins only that container's network namespace, retaining the host Python.
"""
import argparse
import collections
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import socket
import ssl
import stat
import struct
import subprocess
import threading
import time

SCHEME = "stop=3\n0=30-30\n1=300-300\n2=600-600"
BODY = bytes(range(256)) * 256
NAME = "anytls-runtime.test"


def frame(command, sid, payload=b""):
    return struct.pack("!BIH", command, sid, len(payload)) + payload


def readn(conn, size):
    data = bytearray()
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError("incomplete fixture frame")
        data.extend(part)
    return bytes(data)


def unix_json(path, endpoint):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(3)
        conn.connect(str(path))
        conn.sendall(("GET " + endpoint + " HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n").encode())
        chunks = []
        while True:
            part = conn.recv(65536)
            if not part:
                break
            chunks.append(part)
        header, body = b"".join(chunks).split(b"\r\n\r\n", 1)
        assert header.splitlines()[0].split()[1] == b"200", "Unix API status"
        return json.loads(body)


def probe(root):
    fixture = root / "fixture"
    users = json.loads((fixture / "users.json").read_text())
    api = pathlib.Path(json.loads((root / "scope.json").read_text())["socket_path"])
    gate = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            assert gate.wait(4), "fixture gate timed out"
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 19081), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
    thread.start()
    result = {"tls": []}
    try:
        result["controller_version"] = unix_json(api, "/version")["version"]
        result["socket_mode"] = oct(stat.S_IMODE(api.stat().st_mode))
        result["controller_directory_mode"] = oct(stat.S_IMODE(api.parent.stat().st_mode))
        assert result["socket_mode"] == "0o600"
        assert result["controller_directory_mode"] == "0o700"
        # Unix API readiness precedes the listener in some original runtimes.
        # Inspect the isolated network namespace instead of opening extra TLS.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            rows = subprocess.check_output(["ss", "-Hlnt"], text=True).splitlines()
            if any(row.split()[3].rsplit(":", 1)[1] == "7443" for row in rows):
                break
            time.sleep(.02)
        else:
            raise AssertionError("AnyTLS listener not ready")
        for version, user in [(ssl.TLSVersion.TLSv1_2, "fixture-one"), (ssl.TLSVersion.TLSv1_3, "fixture-two")]:
            gate.clear()
            context = ssl.create_default_context(cafile=str(fixture / "cert.pem"))
            context.minimum_version = context.maximum_version = version
            with socket.create_connection(("127.0.0.1", 7443), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=NAME) as conn:
                    conn.settimeout(8)
                    # Real auth padding and an explicit WASTE frame are parsed
                    # by the candidate. The server's advertised scheme is checked.
                    auth = hashlib.sha256(users[user].encode()).digest() + struct.pack("!H", 64) + b"\0" * 64
                    conn.sendall(auth + frame(4, 0, b"v=2\nclient=pcs-runtime-fixture") + frame(0, 0, b"\0" * 17))
                    for sid in (1, 3):
                        target = b"\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 19081)
                        request = b"GET / HTTP/1.0\r\nHost: fixture\r\n\r\n"
                        conn.sendall(frame(1, sid) + frame(2, sid, target + request))
                    deadline = time.monotonic() + 3
                    active = []
                    while time.monotonic() < deadline:
                        active = [row for row in (unix_json(api, "/connections").get("connections") or []) if row.get("metadata", {}).get("inboundUser") == user]
                        if len(active) >= 2:
                            break
                        time.sleep(.02)
                    assert len(active) == 2, "two concurrent authenticated API streams"
                    gate.set()
                    data, closed, commands, padding_ok = {1: b"", 3: b""}, set(), collections.Counter(), False
                    while len(closed) < 2:
                        command, sid, size = struct.unpack("!BIH", readn(conn, 7))
                        payload = readn(conn, size)
                        commands[command] += 1
                        if command == 2 and sid in data:
                            data[sid] += payload
                            assert len(data[sid]) <= 131072, "bounded fixture response"
                        elif command == 3 and sid in data:
                            closed.add(sid)
                        elif command == 6:
                            padding_ok = payload == SCHEME.encode()
                    bodies = [value.split(b"\r\n\r\n", 1)[1] for value in data.values()]
                    assert all(body == BODY for body in bodies), "exact response bytes"
                    assert padding_ok and commands[10] == 1 and commands[7] == 2, "padding/settings/SYNACK policy"
                    result["tls"].append({"version": conn.version(), "active_streams": len(active), "body_bytes": [len(body) for body in bodies], "payloads_ok": True, "padding_update_ok": padding_ok, "user_attribution_ok": True})

        trusted = ssl.create_default_context(cafile=str(fixture / "cert.pem"))
        with socket.create_connection(("127.0.0.1", 7443), timeout=3) as raw:
            with trusted.wrap_socket(raw, server_hostname=NAME) as conn:
                conn.settimeout(3)
                conn.sendall(b"X" * 32 + b"\0\0" + frame(4, 0, b"v=2"))
                try:
                    rejected = conn.recv(1) == b""
                except (ConnectionResetError, ssl.SSLError):
                    rejected = True
                assert rejected, "wrong password accepted"
                result["wrong_auth_rejected"] = rejected
        for label, context, hostname in [("wrong_hostname_rejected", trusted, "wrong-name.test"), ("untrusted_certificate_rejected", ssl.create_default_context(), NAME)]:
            rejected = False
            try:
                with socket.create_connection(("127.0.0.1", 7443), timeout=3) as raw:
                    with context.wrap_socket(raw, server_hostname=hostname):
                        pass
            except ssl.SSLCertVerificationError:
                rejected = True
            assert rejected, label
            result[label] = rejected
        rows = subprocess.check_output(["ss", "-Hlnt"], text=True).splitlines()
        ports = sorted({int(row.split()[3].rsplit(":", 1)[1]) for row in rows})
        assert ports == [7443, 9090, 9091, 19081], "unexpected isolated-fixture TCP listener"
        result["listening_tcp_ports"] = ports
        result["management_tcp_listener"] = True
        result["management_listener_scope"] = "deliberately enabled in isolated security fixture only"
        result["ok"] = True
        return result
    finally:
        gate.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


# Imported probe only. Legacy standalone container launcher intentionally omitted.
