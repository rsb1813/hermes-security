# Defines the bounded internal Hunt discovery and verification data contract.

from __future__ import annotations

import math
from dataclasses import dataclass

from .contracts import Finding, Location, TaskPrediction, parse_prediction


HUNT_CANDIDATE_PROTOCOL_VERSION = 1
HUNT_DISCOVERY_MAX_CANDIDATES = 12
HUNT_FINAL_MAX_FINDINGS = 5
HUNT_SEARCH_PASSES = frozenset(
    {"forward", "backward", "guard", "parser", "state", "general"}
)
_PROOF_STATES = frozenset({"proven", "disproven", "unknown"})
_DISPOSITIONS = frozenset({"accepted", "rejected", "inconclusive"})
_MAX_IDENTIFIER_BYTES = 128
_MAX_FAMILY_BYTES = 96
_MAX_TEXT_BYTES = 2048
_MAX_LOCATION_PATH_BYTES = 240
_MAX_LOCATION_LINE_BYTES = 32


class HuntProtocolError(ValueError):
    """Signals invalid bounded Hunt-only protocol data."""


@dataclass(frozen=True)
class HuntDiscoveryCandidate:
    finding_id: str
    entry_point: Location
    critical_operation: Location
    trace: tuple[Location, ...]
    confidence: float
    vulnerability_family: str
    search_pass: str
    hypothesis: str
    evidence: str
    counterevidence: str
    expected_control: str


@dataclass(frozen=True)
class HuntDiscoveryPrediction:
    task_id: str
    candidates: tuple[HuntDiscoveryCandidate, ...]


@dataclass(frozen=True)
class HuntTerminalDecision:
    candidate_id: str
    disposition: str
    attacker_control: str
    reachability: str
    impact: str
    guard_failure: str
    evidence: str
    counterevidence: str
    proof_gaps: str
    confidence: float


@dataclass(frozen=True)
class HuntVerificationPrediction:
    task_id: str
    findings: tuple[Finding, ...]
    decisions: tuple[HuntTerminalDecision, ...]


def parse_hunt_discovery_prediction(
    value: object, expected_task_id: str
) -> HuntDiscoveryPrediction:
    """Parses one strict internal Hunt discovery response."""
    data = _object(value, "Hunt discovery prediction")
    _exact_fields(data, {"schema_version", "task_id", "candidates"}, "Hunt discovery prediction")
    _schema_version(data["schema_version"])
    task_id = _task_id(data["task_id"], expected_task_id)
    raw_candidates = _list(data["candidates"], "Hunt discovery candidates")
    if len(raw_candidates) > HUNT_DISCOVERY_MAX_CANDIDATES:
        raise HuntProtocolError(
            f"Hunt discovery may contain at most {HUNT_DISCOVERY_MAX_CANDIDATES} candidates"
        )
    candidates = tuple(_discovery_candidate(item) for item in raw_candidates)
    identifiers = [candidate.finding_id for candidate in candidates]
    if len(identifiers) != len(set(identifiers)):
        raise HuntProtocolError("Hunt discovery candidates contain duplicate finding_id values")
    return HuntDiscoveryPrediction(task_id=task_id, candidates=candidates)


def parse_hunt_verification_prediction(
    value: object, expected_task_id: str
) -> HuntVerificationPrediction:
    """Parses one strict internal Hunt verification response."""
    data = _object(value, "Hunt verification prediction")
    _exact_fields(
        data,
        {"schema_version", "task_id", "findings", "decisions"},
        "Hunt verification prediction",
    )
    _schema_version(data["schema_version"])
    task_id = _task_id(data["task_id"], expected_task_id)
    try:
        findings = parse_prediction(
            {"schema_version": data["schema_version"], "task_id": task_id, "findings": data["findings"]}
        ).findings
    except Exception as error:
        raise HuntProtocolError("Hunt verification findings are invalid") from error
    if len(findings) > HUNT_FINAL_MAX_FINDINGS:
        raise HuntProtocolError("Hunt verification findings exceed the final finding limit")
    raw_decisions = _list(data["decisions"], "Hunt verification decisions")
    if len(raw_decisions) > HUNT_DISCOVERY_MAX_CANDIDATES:
        raise HuntProtocolError("Hunt verification decisions exceed the candidate limit")
    decisions = tuple(_terminal_decision(item) for item in raw_decisions)
    identifiers = [decision.candidate_id for decision in decisions]
    if len(identifiers) != len(set(identifiers)):
        raise HuntProtocolError("Hunt verification decisions contain duplicate candidate_id values")
    return HuntVerificationPrediction(task_id=task_id, findings=findings, decisions=decisions)


def _discovery_candidate(value: object) -> HuntDiscoveryCandidate:
    data = _object(value, "Hunt discovery candidate")
    _exact_fields(
        data,
        {
            "finding_id",
            "entry_point",
            "critical_operation",
            "trace",
            "confidence",
            "vulnerability_family",
            "search_pass",
            "hypothesis",
            "evidence",
            "counterevidence",
            "expected_control",
        },
        "Hunt discovery candidate",
    )
    search_pass = _bounded_text(data["search_pass"], "search_pass", _MAX_IDENTIFIER_BYTES)
    if search_pass not in HUNT_SEARCH_PASSES:
        raise HuntProtocolError("search_pass is unsupported")
    return HuntDiscoveryCandidate(
        finding_id=_bounded_text(data["finding_id"], "finding_id", _MAX_IDENTIFIER_BYTES),
        entry_point=_location(data["entry_point"]),
        critical_operation=_location(data["critical_operation"]),
        trace=tuple(_location(item) for item in _list(data["trace"], "trace")),
        confidence=_confidence(data["confidence"]),
        vulnerability_family=_bounded_text(
            data["vulnerability_family"], "vulnerability_family", _MAX_FAMILY_BYTES
        ),
        search_pass=search_pass,
        hypothesis=_bounded_text(data["hypothesis"], "hypothesis", _MAX_TEXT_BYTES),
        evidence=_bounded_text(data["evidence"], "evidence", _MAX_TEXT_BYTES),
        counterevidence=_bounded_text(
            data["counterevidence"], "counterevidence", _MAX_TEXT_BYTES
        ),
        expected_control=_bounded_text(
            data["expected_control"], "expected_control", _MAX_TEXT_BYTES
        ),
    )


def _terminal_decision(value: object) -> HuntTerminalDecision:
    data = _object(value, "Hunt terminal decision")
    _exact_fields(
        data,
        {
            "candidate_id",
            "disposition",
            "attacker_control",
            "reachability",
            "impact",
            "guard_failure",
            "evidence",
            "counterevidence",
            "proof_gaps",
            "confidence",
        },
        "Hunt terminal decision",
    )
    disposition = _bounded_text(data["disposition"], "disposition", _MAX_IDENTIFIER_BYTES)
    if disposition not in _DISPOSITIONS:
        raise HuntProtocolError("disposition is unsupported")
    decision = HuntTerminalDecision(
        candidate_id=_bounded_text(data["candidate_id"], "candidate_id", _MAX_IDENTIFIER_BYTES),
        disposition=disposition,
        attacker_control=_proof(data["attacker_control"], "attacker_control"),
        reachability=_proof(data["reachability"], "reachability"),
        impact=_proof(data["impact"], "impact"),
        guard_failure=_proof(data["guard_failure"], "guard_failure"),
        evidence=_bounded_text(data["evidence"], "evidence", _MAX_TEXT_BYTES, allow_empty=True),
        counterevidence=_bounded_text(
            data["counterevidence"], "counterevidence", _MAX_TEXT_BYTES, allow_empty=True
        ),
        proof_gaps=_bounded_text(data["proof_gaps"], "proof_gaps", _MAX_TEXT_BYTES, allow_empty=True),
        confidence=_confidence(data["confidence"]),
    )
    proofs = (
        decision.attacker_control,
        decision.reachability,
        decision.impact,
        decision.guard_failure,
    )
    if decision.disposition == "accepted":
        if any(proof != "proven" for proof in proofs) or not decision.evidence:
            raise HuntProtocolError("accepted decision requires four proven facts and evidence")
    elif decision.disposition == "rejected":
        if "disproven" not in proofs or not decision.counterevidence:
            raise HuntProtocolError("rejected decision requires a disproven fact and counterevidence")
    elif "unknown" not in proofs or not decision.proof_gaps:
        raise HuntProtocolError("inconclusive decision requires an unknown fact and proof_gaps")
    return decision


def _location(value: object) -> Location:
    data = _object(value, "location")
    _exact_fields(data, {"file", "line"}, "location")
    _bounded_text(data["file"], "location file", _MAX_LOCATION_PATH_BYTES)
    if isinstance(data["line"], str):
        _bounded_text(data["line"], "location line", _MAX_LOCATION_LINE_BYTES)
    try:
        return Location.from_json(data)
    except Exception as error:
        raise HuntProtocolError("candidate location is invalid") from error


def _task_id(value: object, expected: str) -> str:
    task_id = _bounded_text(value, "task_id", _MAX_IDENTIFIER_BYTES)
    if task_id != expected:
        raise HuntProtocolError("prediction task_id does not match the request")
    return task_id


def _proof(value: object, name: str) -> str:
    proof = _bounded_text(value, name, _MAX_IDENTIFIER_BYTES)
    if proof not in _PROOF_STATES:
        raise HuntProtocolError(f"{name} is unsupported")
    return proof


def _confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise HuntProtocolError("confidence must be between 0.0 and 1.0")
    return float(value)


def _bounded_text(value: object, name: str, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise HuntProtocolError(f"{name} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise HuntProtocolError(f"{name} must be valid UTF-8") from error
    if (not allow_empty and not value) or len(encoded) > maximum:
        raise HuntProtocolError(f"{name} is outside the byte limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise HuntProtocolError(f"{name} contains a control character")
    return value


def _schema_version(value: object) -> None:
    if isinstance(value, bool) or value != HUNT_CANDIDATE_PROTOCOL_VERSION:
        raise HuntProtocolError("Hunt protocol schema_version is unsupported")


def _object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise HuntProtocolError(f"{name} must be an object")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise HuntProtocolError(f"{name} must be an array")
    return value


def _exact_fields(value: dict[str, object], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise HuntProtocolError(f"{name} must contain exactly the required fields")
