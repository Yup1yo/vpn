#!/usr/bin/env python3
"""Build a small HAPP subscription from an upstream public feed."""

from __future__ import annotations

import base64
import concurrent.futures
import datetime as dt
import json
import os
import socket
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


SOURCE_URL = os.environ.get(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
    "refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
)
OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "subscription.txt"))
LIMIT = int(os.environ.get("SERVER_LIMIT", "10"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "3.0"))
SUPPORTED_SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "socks",
    "socks5",
    "hysteria2",
    "hy2",
}


@dataclass(frozen=True)
class Candidate:
    config: str
    host: str
    port: int


def _decode_base64(value: str) -> bytes:
    value = urllib.parse.unquote(value).strip()
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value)


def endpoint(config: str) -> tuple[str, int] | None:
    scheme = config.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            payload = config.split("://", 1)[1].split("#", 1)[0]
            data = json.loads(_decode_base64(payload).decode("utf-8"))
            return str(data["add"]), int(data["port"])

        if scheme == "ss":
            body = config.split("://", 1)[1].split("#", 1)[0]
            body = body.split("?", 1)[0]
            if "@" not in body:
                body = _decode_base64(body).decode("utf-8")
                body = body.rsplit("@", 1)[-1]
                host, port = body.rsplit(":", 1)
                return host.strip("[]"), int(port)

        parsed = urllib.parse.urlsplit(config)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port
    except (ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return None


def fetch_candidates() -> list[Candidate]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": "happ-ten-node-subscription/1.0"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        text = response.read().decode("utf-8-sig")

    candidates: list[Candidate] = []
    seen_endpoints: set[tuple[str, int]] = set()
    for raw_line in text.splitlines():
        config = raw_line.strip()
        if not config or config.startswith("#") or "://" not in config:
            continue
        if config.split("://", 1)[0].lower() not in SUPPORTED_SCHEMES:
            continue
        address = endpoint(config)
        if not address or address in seen_endpoints:
            continue
        seen_endpoints.add(address)
        candidates.append(Candidate(config, address[0], address[1]))
    return candidates


def probe(candidate: Candidate) -> tuple[float, Candidate] | None:
    started = time.perf_counter()
    try:
        with socket.create_connection((candidate.host, candidate.port), timeout=TIMEOUT):
            return (time.perf_counter() - started) * 1000, candidate
    except OSError:
        return None


def select_live(candidates: list[Candidate]) -> list[tuple[float, Candidate]]:
    results: list[tuple[float, Candidate]] = []
    workers = min(32, max(1, len(candidates)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for result in executor.map(probe, candidates):
            if result is not None:
                results.append(result)
    results.sort(key=lambda item: item[0])
    return results[:LIMIT]


def render(selected: list[tuple[float, Candidate]]) -> str:
    generated = dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")
    lines = [
        "#profile-title: Наши 10 серверов",
        "#profile-update-interval: 1",
        f"#generated-at: {generated}",
        f"#source: {SOURCE_URL}",
        f"#count: {len(selected)}",
    ]
    lines.extend(item.config for _, item in selected)
    return "\n".join(lines) + "\n"


def main() -> int:
    candidates = fetch_candidates()
    selected = select_live(candidates)
    if len(selected) < LIMIT:
        print(
            f"Refusing to replace subscription: only {len(selected)} of {LIMIT} "
            "unique endpoints accepted a TCP connection.",
            file=sys.stderr,
        )
        return 1
    OUTPUT_PATH.write_text(render(selected), encoding="utf-8", newline="\n")
    for latency, item in selected:
        print(f"{latency:7.1f} ms  {item.host}:{item.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
