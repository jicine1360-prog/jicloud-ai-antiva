import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.enforcement import PolicyValidationError, decide, load_policy, validate_policy


def policy(mode="enforce"):
    return {
        "schema_version": 1,
        "profile": "lab-model",
        "mode": mode,
        "cgroup": "/sys/fs/cgroup/ai-antiva/lab-model",
        "generation": 7,
        "allow": [
            {"direction": "egress", "protocol": "tcp", "family": "ipv4", "cidr": "127.0.0.0/8", "ports": [8080]},
            {"direction": "egress", "protocol": "tcp", "family": "ipv6", "cidr": "::1/128", "ports": [8080]},
        ],
    }


def test_validate_policy_canonical_hash_is_stable():
    first = validate_policy(policy())
    reordered = dict(reversed(list(policy().items())))
    assert first.policy_hash == validate_policy(reordered).policy_hash
    assert first.as_dict()["generation"] == 7


def test_enforce_allows_explicit_ipv4_and_denies_other_destination():
    loaded = validate_policy(policy())
    assert decide(loaded, "127.0.0.1", 8080).action == "allow"
    denied = decide(loaded, "8.8.8.8", 443)
    assert denied.action == "deny"
    assert denied.reason == "default_deny"


def test_enforce_supports_ipv6_and_rejects_unsupported_protocol():
    loaded = validate_policy(policy())
    assert decide(loaded, "::1", 8080).action == "allow"
    denied = decide(loaded, "2001:4860:4860::8888", 443, protocol="udp")
    assert denied.action == "deny"
    assert denied.reason == "unsupported_protocol"


def test_preview_never_returns_enforce_actions():
    loaded = validate_policy(policy("preview"))
    assert decide(loaded, "127.0.0.1", 8080).action == "preview_allow"
    assert decide(loaded, "8.8.8.8", 443).action == "preview_deny"


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "bogus"},
        {"cgroup": "relative/path"},
        {"allow": [{"direction": "egress", "protocol": "udp", "family": "ipv4", "cidr": "0.0.0.0/0", "ports": [53]}]},
        {"allow": [{"direction": "egress", "protocol": "tcp", "family": "ipv4", "cidr": "8.8.8.8", "ports": [443]}]},
        {"allow": [{"direction": "egress", "protocol": "tcp", "family": "ipv4", "cidr": "::/0", "ports": [443]}]},
    ],
)
def test_unsafe_policy_is_rejected(change):
    candidate = policy()
    candidate.update(change)
    with pytest.raises(PolicyValidationError):
        validate_policy(candidate)


def test_invalid_destination_and_port_are_deny_decisions():
    loaded = validate_policy(policy())
    assert decide(loaded, "not-an-ip", 443).reason == "invalid_destination"
    assert decide(loaded, "127.0.0.1", 0).reason == "invalid_port"


def test_load_policy_from_json(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy()), encoding="utf-8")
    assert load_policy(path).profile == "lab-model"


def test_policy_without_an_allow_key_is_rejected():
    missing = policy()
    del missing["allow"]

    with pytest.raises(PolicyValidationError, match="allow is required"):
        validate_policy(missing)


def test_empty_allow_list_is_a_valid_deny_all_policy():
    empty = policy()
    empty["allow"] = []

    assert decide(validate_policy(empty), "127.0.0.1", 8080).reason == "default_deny"


def test_destination_family_is_case_insensitive():
    loaded = validate_policy(policy())

    assert decide(loaded, "127.0.0.1", 8080, family="IPv4").action == "allow"
    assert decide(loaded, "127.0.0.1", 8080, family="IPv6").reason == "family_mismatch"
