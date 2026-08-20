import urllib.parse

from update_subscription import (
    Candidate,
    display_country,
    has_encrypted_transport,
    rename_configs,
    select_country_quotas,
    sing_box_outbound,
)


def test_display_country_translates_source_label():
    config = "vless://id@example.com:443#The%20Netherlands%2C%20Amsterdam%20%7C%20%5BCIDR%5D"
    assert display_country(config) == "🇳🇱 Нидерланды"


def test_plain_vless_is_rejected_but_tls_and_reality_are_allowed():
    assert not has_encrypted_transport(
        "vless://id@example.com:80?type=ws&security=none"
    )
    assert has_encrypted_transport(
        "vless://id@example.com:443?type=ws&security=tls"
    )
    assert has_encrypted_transport(
        "vless://id@example.com:443?type=tcp&security=reality"
    )


def test_sing_box_outbound_keeps_vless_reality_parameters():
    candidate = Candidate(
        "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?"
        "security=reality&sni=www.example.com&pbk=public-key&sid=0011&fp=chrome",
        "example.com",
        443,
    )
    outbound = sing_box_outbound(candidate)
    assert outbound is not None
    assert outbound["type"] == "vless"
    assert outbound["tls"]["reality"]["public_key"] == "public-key"


def test_sing_box_outbound_rejects_plain_or_unsupported_vless():
    plain = Candidate(
        "vless://id@example.com:80?security=none&type=ws", "example.com", 80
    )
    xhttp = Candidate(
        "vless://id@example.com:443?security=tls&type=xhttp", "example.com", 443
    )
    assert sing_box_outbound(plain) is None
    assert sing_box_outbound(xhttp) is None


def test_rename_configs_numbers_duplicates_and_marks_category():
    selected = [
        (12.4, Candidate("vless://a@one.example:443#France", "one.example", 443)),
        (25.6, Candidate("vless://b@two.example:443#France", "two.example", 443)),
    ]
    renamed = rename_configs(selected, "белые списки")
    labels = [urllib.parse.unquote(item.partition("#")[2]) for item in renamed]
    assert labels == [
        "🇫🇷 Франция 1 (белые списки)",
        "🇫🇷 Франция 2 (белые списки)",
    ]


def test_country_quotas_select_only_requested_live_locations(monkeypatch):
    candidates = [
        Candidate("vless://a@one:443#Germany", "one", 443),
        Candidate("vless://b@two:443#Germany", "two", 443),
        Candidate("vless://c@three:443#Poland", "three", 443),
    ]
    monkeypatch.setattr(
        "update_subscription.probe_live",
        lambda items: [(index + 1.0, item) for index, item in enumerate(items)],
    )
    selected = select_country_quotas(
        candidates, {"🇩🇪 Германия": 2, "🇵🇱 Польша": 1}
    )
    assert [item.host for _, item in selected] == ["one", "two", "three"]
