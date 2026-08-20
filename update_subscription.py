#!/usr/bin/env python3
"""Build a 20-node HAPP subscription from maintained public feeds."""

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
BLACK_FALLBACK_SOURCE_URL = os.environ.get(
    "BLACK_FALLBACK_SOURCE_URL",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
    "refs/heads/main/BLACK_VLESS_RUS.txt",
)
BLACK_ALL_FALLBACK_SOURCE_URL = os.environ.get(
    "BLACK_ALL_FALLBACK_SOURCE_URL",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
    "refs/heads/main/BLACK_SS%2BAll_RUS.txt",
)
OUTPUT_PATH = Path(os.environ.get("OUTPUT_PATH", "subscription.txt"))
BLACK_LIMIT = int(os.environ.get("BLACK_SERVER_LIMIT", "15"))
WHITE_LIMIT = int(os.environ.get("WHITE_SERVER_LIMIT", "5"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "2.5"))
PROBE_ATTEMPTS = max(1, int(os.environ.get("PROBE_ATTEMPTS", "3")))
MAX_REGULAR_PER_LOCATION = max(
    1, int(os.environ.get("MAX_REGULAR_PER_LOCATION", "3"))
)
SUPPORTED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "socks", "socks5", "hysteria2", "hy2"
}

COUNTRY_NAMES = (
    ("the netherlands", "🇳🇱 Нидерланды"),
    ("netherlands", "🇳🇱 Нидерланды"),
    ("united kingdom", "🇬🇧 Великобритания"),
    ("united states", "🇺🇸 США"),
    ("germany", "🇩🇪 Германия"),
    ("france", "🇫🇷 Франция"),
    ("poland", "🇵🇱 Польша"),
    ("latvia", "🇱🇻 Латвия"),
    ("estonia", "🇪🇪 Эстония"),
    ("finland", "🇫🇮 Финляндия"),
    ("canada", "🇨🇦 Канада"),
    ("russia", "🇷🇺 Россия"),
    ("sweden", "🇸🇪 Швеция"),
    ("norway", "🇳🇴 Норвегия"),
    ("switzerland", "🇨🇭 Швейцария"),
    ("austria", "🇦🇹 Австрия"),
    ("spain", "🇪🇸 Испания"),
    ("italy", "🇮🇹 Италия"),
    ("romania", "🇷🇴 Румыния"),
    ("turkey", "🇹🇷 Турция"),
    ("japan", "🇯🇵 Япония"),
    ("singapore", "🇸🇬 Сингапур"),
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


def has_encrypted_transport(config: str) -> bool:
    """Reject plain VLESS links; other supported protocols encrypt by design."""
    scheme = config.split("://", 1)[0].lower()
    if scheme != "vless":
        return True
    try:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(config).query)
    except ValueError:
        return False
    return query.get("security", [""])[0].lower() in {"tls", "reality"}


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
        if not has_encrypted_transport(config):
            continue
        address = endpoint(config)
        if not address or address[0] in seen_hosts:
            continue
        seen_hosts.add(address[0])
        candidates.append(Candidate(config, address[0], address[1]))
    return candidates


def merge_candidates(*groups: list[Candidate]) -> list[Candidate]:
    merged: list[Candidate] = []
    seen_hosts: set[str] = set()
    for group in groups:
        for item in group:
            if item.host in seen_hosts:
                continue
            seen_hosts.add(item.host)
            merged.append(item)
    return merged


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
    # A node with a low one-off result but large jitter is less useful than a
    # slightly slower, stable one. The score still strongly favors low latency.
    median = statistics.median(latencies)
    jitter = max(latencies) - min(latencies)
    return median + jitter * 0.35, candidate


def select_live(
    candidates: list[Candidate], limit: int
) -> list[tuple[float, Candidate]]:
    return probe_live(candidates)[:limit]


def probe_live(candidates: list[Candidate]) -> list[tuple[float, Candidate]]:
    results: list[tuple[float, Candidate]] = []
    workers = min(32, max(1, len(candidates)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for result in executor.map(probe, candidates):
            if result is not None:
                results.append(result)
    results.sort(key=lambda item: item[0])
    return results


def select_country_quotas(
    candidates: list[Candidate], quotas: dict[str, int]
) -> list[tuple[float, Candidate]]:
    live = probe_live(candidates)
    selected: list[tuple[float, Candidate]] = []
    missing: list[str] = []
    for country, required in quotas.items():
        matches = [
            item for item in live if display_country(item[1].config) == country
        ][:required]
        selected.extend(matches)
        if len(matches) < required:
            missing.append(f"{country}: {len(matches)}/{required}")
    if missing:
        raise RuntimeError("not enough live country nodes: " + ", ".join(missing))
    return selected


def select_diverse(
    candidates: list[Candidate], limit: int, max_per_location: int = 2
) -> list[tuple[float, Candidate]]:
    """Prefer low latency while preventing one location from taking the whole list.

    If the diversity pass cannot fill the requested amount, use the next fastest
    live endpoints. This keeps the published feed complete during source churn.
    """
    live = probe_live(candidates)
    selected: list[tuple[float, Candidate]] = []
    counts: collections.Counter[str] = collections.Counter()
    selected_endpoints: set[tuple[str, int]] = set()
    for item in live:
        country = display_country(item[1].config)
        if counts[country] >= max_per_location:
            continue
        selected.append(item)
        selected_endpoints.add((item[1].host, item[1].port))
        counts[country] += 1
        if len(selected) == limit:
            return selected
    for item in live:
        endpoint_key = (item[1].host, item[1].port)
        if endpoint_key in selected_endpoints:
            continue
        selected.append(item)
        selected_endpoints.add(endpoint_key)
        if len(selected) == limit:
            break
    return selected


def display_country(config: str) -> str:
    fragment = config.partition("#")[2]
    label = urllib.parse.unquote(fragment).lower()
    for needle, translated in COUNTRY_NAMES:
        if needle in label:
            return translated
    if "anycast" in label:
        return "🌐 Anycast"
    return "🌐 VPN-сервер"


def rename_configs(
    selected: list[tuple[float, Candidate]], category: str
) -> list[str]:
    totals = collections.Counter(display_country(item.config) for _, item in selected)
    indexes: collections.Counter[str] = collections.Counter()
    renamed: list[str] = []
    for _, item in selected:
        country = display_country(item.config)
        indexes[country] += 1
        number = f" {indexes[country]}" if totals[country] > 1 else ""
        label = f"{country}{number} ({category})"
        renamed.append(item.config.partition("#")[0] + "#" + urllib.parse.quote(label))
    return renamed


def render(
    black: list[tuple[float, Candidate]], white: list[tuple[float, Candidate]]
) -> str:
    generated = dt.datetime.now(dt.timezone.utc).astimezone().isoformat(
        timespec="seconds"
    )
    lines = [
        "#profile-title: NotV VPN — 20 быстрых серверов",
        "#profile-update-interval: 1",
        f"#generated-at: {generated}",
        f"#count: {len(black) + len(white)}",
        f"#black-source: {BLACK_SOURCE_URL}",
        f"#black-fallback-source: {BLACK_FALLBACK_SOURCE_URL}",
        f"#black-all-fallback-source: {BLACK_ALL_FALLBACK_SOURCE_URL}",
        f"#white-source: {WHITE_SOURCE_URL}",
        f"#black-count: {len(black)}",
        f"#white-count: {len(white)}",
        f"#probe-attempts: {PROBE_ATTEMPTS}",
        "#selection: lowest median TCP-connect latency among stable encrypted public nodes",
        "# Обычные подключения (чёрные списки)",
    ]
    lines.extend(rename_configs(black, "обычный"))
    lines.append("# Резерв для режима белых списков в РФ")
    lines.extend(rename_configs(white, "белые списки"))
    return "\n".join(lines) + "\n"


def main() -> int:
    black_candidates = merge_candidates(
        fetch_candidates(BLACK_SOURCE_URL),
        fetch_candidates(BLACK_FALLBACK_SOURCE_URL),
        fetch_candidates(BLACK_ALL_FALLBACK_SOURCE_URL),
    )
    black = select_diverse(
        black_candidates,
        BLACK_LIMIT,
        max_per_location=MAX_REGULAR_PER_LOCATION,
    )
    black_endpoints = {(item.host, item.port) for _, item in black}
    white_candidates = [
        item for item in fetch_candidates(WHITE_SOURCE_URL)
        if (item.host, item.port) not in black_endpoints
    ]
    white = select_diverse(white_candidates, WHITE_LIMIT, max_per_location=2)
    if len(black) < BLACK_LIMIT or len(white) < WHITE_LIMIT:
        print(
            "Keeping previous subscription; the fresh pool is too small: "
            f"black={len(black)}/{BLACK_LIMIT}, white={len(white)}/{WHITE_LIMIT} "
            f"accepted {PROBE_ATTEMPTS}/{PROBE_ATTEMPTS} TCP probes.",
            file=sys.stderr,
        )
        # Do not replace a usable feed with a partial set during a temporary
        # source outage. A following five-minute run will try again.
        return 0
    OUTPUT_PATH.write_text(render(black, white), encoding="utf-8", newline="\n")
    for group, selected in (("BLACK", black), ("WHITE", white)):
        for latency, item in selected:
            print(f"{group:5} {latency:7.1f} ms  {item.host}:{item.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
