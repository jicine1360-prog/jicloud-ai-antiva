"""Pure, side-effect-free egress policy validation and simulation.

This module deliberately does not install firewall/eBPF rules or open sockets.
It is the Stage A policy contract used before a future privileged enforcer.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any


class PolicyValidationError(ValueError):
    """Raised when a policy is unsafe or ambiguous for enforcement."""


@dataclass(frozen=True)
class EgressRule:
    protocol: str
    family: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    ports: frozenset[int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "direction": "egress",
            "protocol": self.protocol,
            "family": self.family,
            "cidr": str(self.network),
            "ports": sorted(self.ports),
        }


@dataclass(frozen=True)
class EgressPolicy:
    profile: str
    mode: str
    cgroup: str
    generation: int
    rules: tuple[EgressRule, ...]
    policy_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "profile": self.profile,
            "mode": self.mode,
            "cgroup": self.cgroup,
            "generation": self.generation,
            "allow": [rule.as_dict() for rule in self.rules],
        }


@dataclass(frozen=True)
class EgressDecision:
    profile: str
    cgroup: str
    generation: int
    policy_hash: str
    destination: str
    port: int | None
    protocol: str
    family: str | None
    action: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "cgroup": self.cgroup,
            "generation": self.generation,
            "policy_hash": self.policy_hash,
            "destination": self.destination,
            "port": self.port,
            "protocol": self.protocol,
            "family": self.family,
            "action": self.action,
            "reason": self.reason,
        }


def _require_string(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise PolicyValidationError(f"invalid {field}")
    return value


def _require_int(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PolicyValidationError(f"invalid {field}")
    return value


def _canonical_hash(data: dict[str, Any]) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_ports(value: Any) -> frozenset[int]:
    if not isinstance(value, list) or not value or len(value) > 1024:
        raise PolicyValidationError("ports must be a non-empty list")
    ports: set[int] = set()
    for port in value:
        parsed = _require_int(port, "port", minimum=1)
        if parsed > 65535:
            raise PolicyValidationError("port must be between 1 and 65535")
        ports.add(parsed)
    return frozenset(ports)


def _parse_rule(value: Any) -> EgressRule:
    if not isinstance(value, dict):
        raise PolicyValidationError("each allow rule must be an object")
    if value.get("direction") != "egress":
        raise PolicyValidationError("only egress rules are supported")
    protocol = _require_string(value.get("protocol"), "protocol", 16).lower()
    if protocol != "tcp":
        raise PolicyValidationError("only tcp rules are supported")
    family = _require_string(value.get("family"), "family", 8).lower()
    if family not in {"ipv4", "ipv6"}:
        raise PolicyValidationError("family must be ipv4 or ipv6")
    cidr = _require_string(value.get("cidr"), "cidr", 64)
    if "/" not in cidr:
        raise PolicyValidationError("cidr must include an explicit prefix length")
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError as error:
        raise PolicyValidationError(f"invalid cidr: {cidr}") from error
    if (network.version == 4 and family != "ipv4") or (network.version == 6 and family != "ipv6"):
        raise PolicyValidationError("cidr address family does not match family")
    return EgressRule(protocol, family, network, _parse_ports(value.get("ports")))


def validate_policy(data: Any) -> EgressPolicy:
    """Validate and normalize a JSON-compatible policy without side effects."""

    if not isinstance(data, dict):
        raise PolicyValidationError("policy must be an object")
    if data.get("schema_version", 1) != 1:
        raise PolicyValidationError("unsupported schema_version")
    profile = _require_string(data.get("profile"), "profile", 64)
    mode = _require_string(data.get("mode"), "mode", 16).lower()
    if mode not in {"preview", "enforce"}:
        raise PolicyValidationError("mode must be preview or enforce")
    cgroup = _require_string(data.get("cgroup"), "cgroup", 512)
    if not cgroup.startswith("/") or "\x00" in cgroup:
        raise PolicyValidationError("cgroup must be an absolute path")
    generation = _require_int(data.get("generation", 1), "generation", minimum=1)
    if "allow" not in data:
        raise PolicyValidationError("allow is required")
    raw_rules = data["allow"]
    if not isinstance(raw_rules, list) or len(raw_rules) > 4096:
        raise PolicyValidationError("allow must be a list with at most 4096 rules")
    rules = tuple(_parse_rule(rule) for rule in raw_rules)
    normalized = {
        "schema_version": 1,
        "profile": profile,
        "mode": mode,
        "cgroup": cgroup,
        "generation": generation,
        "allow": [rule.as_dict() for rule in rules],
    }
    return EgressPolicy(profile, mode, cgroup, generation, rules, _canonical_hash(normalized))


def load_policy(path: str | Path) -> EgressPolicy:
    """Load a JSON policy file. YAML is intentionally not implicit."""

    source = Path(path).expanduser()
    try:
        with source.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyValidationError(f"cannot load policy: {error}") from error
    return validate_policy(data)


def decide(
    policy: EgressPolicy,
    destination: str,
    port: int,
    protocol: str = "tcp",
    family: str | None = None,
) -> EgressDecision:
    """Simulate one outbound connect decision; never changes host networking."""

    normalized_protocol = protocol.lower() if isinstance(protocol, str) else ""
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return _decision(policy, destination, None, normalized_protocol, family, "invalid_destination")
    inferred_family = "ipv4" if address.version == 4 else "ipv6"
    family = family.lower() if isinstance(family, str) else family
    if family is not None and family != inferred_family:
        return _decision(policy, destination, None, normalized_protocol, family, "family_mismatch")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return _decision(policy, str(address), None, normalized_protocol, inferred_family, "invalid_port")
    if normalized_protocol != "tcp":
        return _decision(policy, str(address), port, normalized_protocol, inferred_family, "unsupported_protocol")
    matched = any(
        rule.protocol == normalized_protocol
        and rule.family == inferred_family
        and port in rule.ports
        and address in rule.network
        for rule in policy.rules
    )
    reason = "allow_rule_match" if matched else "default_deny"
    action = ("preview_allow" if matched else "preview_deny") if policy.mode == "preview" else ("allow" if matched else "deny")
    return _decision(policy, str(address), port, normalized_protocol, inferred_family, reason, action)


def _decision(
    policy: EgressPolicy,
    destination: str,
    port: int | None,
    protocol: str,
    family: str | None,
    reason: str,
    action: str | None = None,
) -> EgressDecision:
    if action is None:
        action = "preview_deny" if policy.mode == "preview" else "deny"
    return EgressDecision(
        policy.profile,
        policy.cgroup,
        policy.generation,
        policy.policy_hash,
        destination,
        port,
        protocol,
        family,
        action,
        reason,
    )
