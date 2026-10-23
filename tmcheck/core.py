"""tmcheck: a checker for threat models kept as YAML in the repository.

Implements the rules from README.md ("What to build"). Keep the names and signatures
exactly as they are: the grader imports them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

import yaml

SECTIONS = ("zones", "elements", "flows", "threats")
ELEMENT_KINDS = ("external_entity", "process", "data_store")
THREAT_STATUSES = ("open", "mitigated", "accepted")
STRIDE_ORDER = ("S", "T", "R", "I", "D", "E")
SECURE_PROTOCOLS = ("https", "tls", "mtls", "sftp", "ssh")


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"


def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as exc:
        raise ModelError(f"cannot read {path!r}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ModelError(f"cannot parse {path!r}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ModelError(
            f"top level of {path!r} must be a mapping, got {type(data).__name__}")
    model = {}
    for section in SECTIONS:
        value = data.get(section)
        if value is None:
            value = []
        if not isinstance(value, list):
            raise ModelError(
                f"section {section!r} must be a list, got {type(value).__name__}")
        model[section] = value
    return model


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set("STRIDE")
    if kind == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"unknown element kind: {kind!r}")


def _is_score(value) -> bool:
    """A score is an integer 1..5; booleans and floats like 4.0 are not scores."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 5


def _has_text(value) -> bool:
    """True when the value is a string with non-whitespace content."""
    return isinstance(value, str) and value.strip() != ""


def _natural_key(ref: str):
    """Sort key so that T2 comes before T10: digits compare numerically."""
    parts = re.split(r"(\d+)", str(ref))
    return [(int(p) if p.isdigit() else p, p.isdigit()) for p in parts if p != ""]


def _index(model: dict, section: str) -> dict:
    """id -> item for a section, skipping items that are not mappings or have no id."""
    out = {}
    for item in model.get(section, []):
        if isinstance(item, dict) and "id" in item:
            out[item["id"]] = item
    return out


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues: set[tuple[str, str, str]] = set()

    def add(ref, code, message=""):
        issues.add((str(ref), code, message))

    # DUPLICATE_ID: zones, elements, flows and threats share one id space.
    seen: dict = {}
    for section in SECTIONS:
        for item in model.get(section, []):
            if isinstance(item, dict) and "id" in item:
                seen[item["id"]] = seen.get(item["id"], 0) + 1
    for rid, count in seen.items():
        if count > 1:
            add(rid, "DUPLICATE_ID",
                f"id {rid!r} used {count} times in the model")

    zones = _index(model, "zones")
    elements = _index(model, "elements")
    flows = _index(model, "flows")

    # Elements
    for el in model.get("elements", []):
        if not isinstance(el, dict):
            continue
        eid = el.get("id")
        kind = el.get("kind")
        if kind not in ELEMENT_KINDS:
            add(eid, "BAD_KIND", f"unknown kind {kind!r}")
        if el.get("zone") not in zones:
            add(eid, "UNKNOWN_ZONE", f"zone {el.get('zone')!r} is not defined")

    # Flows
    for fl in model.get("flows", []):
        if not isinstance(fl, dict):
            continue
        fid = fl.get("id")
        source = fl.get("source")
        target = fl.get("target")
        if source == target:
            # A self-loop is an invalid flow whether or not the id resolves.
            add(fid, "INVALID_FLOW", "source equals target")
            continue
        bad_ref = False
        if source not in elements:
            add(fid, "UNKNOWN_REF", f"source {source!r} is not an element")
            bad_ref = True
        if target not in elements:
            add(fid, "UNKNOWN_REF", f"target {target!r} is not an element")
            bad_ref = True
        if bad_ref:
            continue
        if elements[source].get("kind") != "process" and elements[target].get("kind") != "process":
            add(fid, "INVALID_FLOW", "neither end is a process")

    # Threats
    for th in model.get("threats", []):
        if not isinstance(th, dict):
            continue
        tid = th.get("id")
        target = th.get("target")
        target_el = elements.get(target)
        target_fl = flows.get(target)
        if target_el is None and target_fl is None:
            add(tid, "UNKNOWN_REF",
                f"target {target!r} is neither an element nor a flow")
        category = th.get("category")
        if (
            target_el is not None
            and target_el.get("kind") in ELEMENT_KINDS
            or target_fl is not None
        ):
            # Only check applicability when the category is valid and the target resolves.
            if (
                isinstance(category, str)
                and category in STRIDE_ORDER
                and (target_el is not None or target_fl is not None)
            ):
                if target_fl is not None:
                    apps = applicable("data_flow")
                else:
                    apps = applicable(
                        target_el.get("kind"), is_log=bool(target_el.get("is_log"))
                    )
                if category not in apps:
                    add(tid, "INAPPLICABLE_CATEGORY",
                        f"{category} does not apply to {target!r}")
        if not (isinstance(category, str) and category in STRIDE_ORDER):
            add(tid, "BAD_CATEGORY",
                f"category {category!r} is not one of S T R I D E")
        if not _is_score(th.get("likelihood")):
            add(tid, "BAD_SCORE",
                f"likelihood {th.get('likelihood')!r} is not an integer 1..5")
        if not _is_score(th.get("impact")):
            add(tid, "BAD_SCORE",
                f"impact {th.get('impact')!r} is not an integer 1..5")
        status = th.get("status")
        if status not in THREAT_STATUSES:
            add(tid, "BAD_STATUS",
                f"status {status!r} is not one of open/mitigated/accepted")
        elif status == "mitigated" and not _has_text(th.get("mitigation")):
            add(tid, "MISSING_MITIGATION",
                "mitigated threat has no mitigation text")
        elif status == "accepted" and not _has_text(th.get("justification")):
            add(tid, "MISSING_JUSTIFICATION",
                "accepted threat has no justification text")

    return sorted(Issue(*t) for t in issues)


def _crossing(model: dict):
    """Yield (flow_id, source_element, target_element) for valid flows crossing zone boundaries."""
    elements = _index(model, "elements")
    zones = _index(model, "zones")
    for fl in model.get("flows", []):
        if not isinstance(fl, dict):
            continue
        source = elements.get(fl.get("source"))
        target = elements.get(fl.get("target"))
        if source is None or target is None:
            continue  # unknown ends are skipped
        if fl.get("source") == fl.get("target"):
            continue
        sz = zones.get(source.get("zone"))
        tz = zones.get(target.get("zone"))
        if sz is None or tz is None:
            continue
        if sz.get("trust") != tz.get("trust"):
            yield fl, source, target, sz, tz


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    return [fl["id"] for fl, *_ in _crossing(model)]


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    flows = _index(model, "flows")
    elements = _index(model, "elements")

    scope: dict[str, str] = {}  # ref -> kind ("data_flow" or element kind)
    for fl, source, target, *_ in _crossing(model):
        scope[fl["id"]] = "data_flow"
        for el in (source, target):
            kind = el.get("kind")
            if kind in ELEMENT_KINDS:
                scope[el["id"]] = kind

    covered: set[tuple[str, str]] = set()
    for th in model.get("threats", []):
        if not isinstance(th, dict):
            continue
        category = th.get("category")
        target = th.get("target")
        if isinstance(category, str) and category in STRIDE_ORDER and target in scope:
            covered.add((target, category))

    gaps = []
    for ref, kind in scope.items():
        is_log = bool(elements.get(ref, {}).get("is_log"))
        apps = applicable(kind, is_log=is_log)
        for category in STRIDE_ORDER:
            if category in apps and (ref, category) not in covered:
                gaps.append(Gap(ref, category))
    return sorted(gaps)


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    issues: set[tuple[str, str, str]] = set()

    for fl, source, target, sz, tz in _crossing(model):
        fid = fl["id"]
        protocol = fl.get("protocol")
        if not (isinstance(protocol, str) and protocol.lower() in SECURE_PROTOCOLS):
            issues.add((str(fid), "UNENCRYPTED_CROSSING",
                       f"flow {fid!r} crosses zones over {protocol!r}"))
        if tz.get("trust") > sz.get("trust") and fl.get("authenticated") is not True:
            issues.add((str(fid), "UNAUTHENTICATED_INBOUND",
                       f"flow {fid!r} enters a more trusted zone unauthenticated"))

    i_threat_targets = {
        th.get("target")
        for th in model.get("threats", [])
        if isinstance(th, dict) and th.get("category") == "I"
    }
    for el in model.get("elements", []):
        if (
            isinstance(el, dict)
            and el.get("kind") == "data_store"
            and el.get("holds_pii") is True
            and el.get("id") not in i_threat_targets
        ):
            issues.add((str(el["id"]), "PII_STORE_WITHOUT_I_THREAT",
                       "store holds PII with no I threat"))

    return sorted(Issue(*t) for t in issues)


def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    entries = []
    for th in model.get("threats", []):
        if not isinstance(th, dict) or th.get("status") != "open":
            continue
        likelihood = th.get("likelihood")
        impact = th.get("impact")
        if not _is_score(likelihood) or not _is_score(impact):
            continue
        score = likelihood * impact
        if score >= 15:
            level = "high"
        elif score >= 8:
            level = "medium"
        else:
            level = "low"
        entries.append((score, impact, _natural_key(
            th.get("id", "")), th["id"], level))
    entries.sort(key=lambda e: (-e[0], -e[1], e[2]))
    return [RankedThreat(id=rid, score=score, level=level) for score, impact, _, rid, level in entries]
