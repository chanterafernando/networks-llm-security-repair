#!/usr/bin/env python3
"""
Sonda de red (opcional, para entender y defender la parte de redes).

Descompone manualmente lo que el SDK de OpenAI hace "por debajo":
    1. DNS   : api.openai.com -> direcciones IP          (socket.getaddrinfo)
    2. TCP   : three-way handshake al puerto 443          (socket.create_connection)
    3. TLS   : handshake, versión, cifrado y certificado  (ssl.wrap_socket)
    4. HTTPS : GET /v1/models SIN API key -> se espera HTTP 401 Unauthorized

No envía la API key ni código. Guarda results/network_probe.json.
Uso:  python3 netprobe.py
"""
import datetime as dt
import json
import socket
import ssl
import time

import config as C

HOST, PORT = C.API_HOST, 443


def ms(t0):
    return round((time.perf_counter() - t0) * 1000, 2)


def main():
    out = {"host": HOST, "port": PORT, "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}

    t0 = time.perf_counter()
    infos = socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM)
    out["dns_ms"] = ms(t0)
    out["dns_addresses"] = sorted({i[4][0] for i in infos})
    ip = infos[0][4][0]

    t0 = time.perf_counter()
    sock = socket.create_connection((ip, PORT), timeout=10)
    out["tcp_connect_ms"] = ms(t0)
    out["connected_ip"] = ip

    ctx = ssl.create_default_context()
    t0 = time.perf_counter()
    tls = ctx.wrap_socket(sock, server_hostname=HOST)   # SNI + verificación del certificado
    out["tls_handshake_ms"] = ms(t0)
    out["tls_version"] = tls.version()
    out["tls_cipher"] = tls.cipher()[0]
    cert = tls.getpeercert()
    out["cert_subject"] = dict(x[0] for x in cert["subject"])
    out["cert_issuer"] = dict(x[0] for x in cert["issuer"])
    out["cert_not_after"] = cert["notAfter"]

    req = (f"GET /v1/models HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: netprobe\r\n"
           "Accept: application/json\r\nConnection: close\r\n\r\n").encode()
    t0 = time.perf_counter()
    tls.sendall(req)
    first = tls.recv(4096)
    out["http_ttfb_ms"] = ms(t0)
    status_line = first.split(b"\r\n", 1)[0].decode(errors="replace")
    out["http_status_line"] = status_line
    tls.close()

    C.RESULTS.mkdir(parents=True, exist_ok=True)
    (C.RESULTS / "network_probe.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    for k, v in out.items():
        print(f"{k:18}: {v}")


if __name__ == "__main__":
    main()
