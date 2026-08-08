#!/usr/bin/env python3
"""Build a small mixed HAPP subscription from public tested feeds."""

from __future__ import annotations

import base64
import collections
import concurrent.futures
import datetime as dt
import json
import os
import socket
import statistics
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

BLACK_SOURCE_URL = os.environ.get(
    "BLACK_SOURCE_URL",
    os.environ.get(
        "SOURCE_URL",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
        "refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    ),
)
WHITE_SOURCE_URL = os.environ.get(
    "WHITE_SOURCE_URL",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
    "refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
)
OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "subscription.txt"))
BLACK_LIMIT = int(os.environ.get("BLACK_SERVER_LIMIT", "10"))
WHITE_LIMIT = int(os.environ.get("WHITE_SERVER_LIMIT", "5"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "3.0"))
PROBE_ATTEMPTS = max(1, int(os.environ.get("PROBE_ATTEMPTS", "2")))
SUPPORTED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "socks", "socks5", "hysteria2", "hy2"
}

COUNTRY_NAMES = (
    ("the netherlands", "Нидерланды"),
    ("netherlands", "Нидерланды"),
    ("united kingdom", "Великобритания"),
    ("united states", "США"),
    ("germany", "Германия"),
    ("france", "Франция"),
    ("poland", "Польша"),
    ("latvia", "Латвия"),
    ("estonia", "Эстония"),
    ("finland", "Финляндия"),
    ("canada", "Канада"),
    ("russia", "Россия"),
    ("sweden", "Швеция"),
    ("norway", "Норвегия"),
    ("switzerland", "Швейцария"),
    ("austria", "Австрия"),
    ("spain", "Испания"),
    ("italy", "Италия"),
    ("romania", "Румыния"),
    ("turkey", "Турция"),
    ("japan", "Япония"),
    ("singapore", "Сингапур"),
)


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
            body = config.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
            if "@" not in body:
                body = _decode_base64(body).decode("utf-8").rsplit("@", 1)[-1]
                host, port = body.rsplit(":", 1)
                return host.strip("[]"), int(port)
        parsed = urllib.parse.urlsplit(config)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port
    except (ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return None


def fetch_candidates(source_url: str) -> list[Candidate]:
    request = urllib.request.Request(
        source_url, headers={"User-Agent": "happ-mixed-subscription/2.0"}
    )
    last_error: OSError | None = None
    text: str | None = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                text = response.read().decode("utf-8-sig")
            break
        except OSError as error:
            last_error = error
            if attempt < 3:
                time.sleep(attempt * 2)
    if text is None:
        raise RuntimeError(f"could not download feed: {source_url}") from last_error

    candidates: list[Candidate] = []
    seen_hosts: set[str] = set()
    for raw_line in text.splitlines():
        config = raw_line.strip()
        if not config or config.startswith("#") or "://" not in config:
            continue
        if config.split("://", 1)[0].lower() not in SUPPORTED_SCHEMES:
            continue
        address = endpoint(config)
        if not address or address[0] in seen_hosts:
            continue
        seen_hosts.add(address[0])
        candidates.append(Candidate(config, address[0], address[1]))
    return candidates


def probe(candidate: Candidate) -> tuple[float, Candidate] | None:
    latencies: list[float] = []
    for _ in range(PROBE_ATTEMPTS):
        started = time.perf_counter()
        try:
            with socket.create_connection(
                (candidate.host, candidate.port), timeout=TIMEOUT
            ):
                latencies.append((time.perf_counter() - started) * 1000)
        except OSError:
            return None
    return statistics.median(latencies), candidate


def select_live(
    candidates: list[Candidate], limit: int
) -> list[tuple[float, Candidate]]:
    results: list[tuple[float, Candidate]] = []
    workers = min(32, max(1, len(candidates)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for result in executor.map(probe, candidates):
            if result is not None:
                results.append(result)
    results.sort(key=lambda item: item[0])
    return results[:limit]


def display_country(config: str) -> str:
    fragment = config.partition("#")[2]
    label = urllib.parse.unquote(fragment).lower()
    for needle, translated in COUNTRY_NAMES:
        if needle in label:
            return translated
    if "anycast" in label:
        return "Anycast"
    return "VPN-сервер"


def rename_configs(
    selected: list[tuple[float, Candidate]], category: str
) -> list[str]:
    totals = collections.Counter(display_country(item.config) for _, item in selected)
    indexes: collections.Counter[str] = collections.Counter()
    renamed: list[str] = []
    for latency, item in selected:
        country = display_country(item.config)
        indexes[country] += 1
        number = f" {indexes[country]}" if totals[country] > 1 else ""
        label = f"{country}{number} ({category}) • TCP {max(1, round(latency))} мс"
        renamed.append(item.config.partition("#")[0] + "#" + urllib.parse.quote(label))
    return renamed


def render(
    black: list[tuple[float, Candidate]], white: list[tuple[float, Candidate]]
) -> str:
    generated = dt.datetime.now(dt.timezone.utc).astimezone().isoformat(
        timespec="seconds"
    )
    lines = [
        "#profile-title: Наши VPN — обычные + белые списки",
        "#profile-update-interval: 1",
        f"#generated-at: {generated}",
        f"#count: {len(black) + len(white)}",
        f"#black-source: {BLACK_SOURCE_URL}",
        f"#white-source: {WHITE_SOURCE_URL}",
        f"#black-count: {len(black)}",
        f"#white-count: {len(white)}",
        "# Обычные подключения (чёрные списки)",
    ]
    lines.extend(rename_configs(black, "обычный"))
    lines.append("# Резерв для режима белых списков в РФ")
    lines.extend(rename_configs(white, "белые списки"))
    return "\n".join(lines) + "\n"


def main() -> int:
    black = select_live(fetch_candidates(BLACK_SOURCE_URL), BLACK_LIMIT)
    black_endpoints = {(item.host, item.port) for _, item in black}
    white_candidates = [
        item for item in fetch_candidates(WHITE_SOURCE_URL)
        if (item.host, item.port) not in black_endpoints
    ]
    white = select_live(white_candidates, WHITE_LIMIT)
    if len(black) < BLACK_LIMIT or len(white) < WHITE_LIMIT:
        print(
            "Refusing to replace subscription: "
            f"black={len(black)}/{BLACK_LIMIT}, white={len(white)}/{WHITE_LIMIT} "
            f"accepted {PROBE_ATTEMPTS}/{PROBE_ATTEMPTS} TCP probes.",
            file=sys.stderr,
        )
        return 1
    OUTPUT_PATH.write_text(render(black, white), encoding="utf-8", newline="\n")
    for group, selected in (("BLACK", black), ("WHITE", white)):
        for latency, item in selected:
            print(f"{group:5} {latency:7.1f} ms  {item.host}:{item.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
