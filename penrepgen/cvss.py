"""CVSS v3.1 vector parser and base score calculator."""

from __future__ import annotations

import math
from typing import Dict, Tuple

# Valid metric values for CVSS v3.1 Base Metrics
VALID_METRICS: Dict[str, Tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("N", "L", "H"),
    "I": ("N", "L", "H"),
    "A": ("N", "L", "H"),
}

REQUIRED_METRIC_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Metric weights
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

# Scope-dependent PR weights
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},  # Scope Changed
}


class CVSSValidationError(ValueError):
    """Raised when a CVSS vector string fails validation."""


def roundup(val: float) -> float:
    """CVSS v3.1 floating-point safe roundup function to 1 decimal place.

    Defined in the CVSS v3.1 specification (Appendix A).
    """
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return round(int_val / 100000.0, 1)
    return round((math.floor(int_val / 10000) + 1) / 10.0, 1)


def parse_vector(vector_str: str) -> Dict[str, str]:
    """Parse and validate a CVSS v3.1 vector string into a metric dictionary.

    Args:
        vector_str: Vector string starting with 'CVSS:3.1/'.

    Returns:
        Dict mapping metric names to their values (e.g. {'AV': 'N', ...}).

    Raises:
        CVSSValidationError: If the vector has an invalid prefix, missing,
            duplicate, or invalid metric values.
    """
    if not isinstance(vector_str, str) or not vector_str.strip():
        raise CVSSValidationError("CVSS vector string cannot be empty.")

    cleaned = vector_str.strip()
    parts = cleaned.split("/")

    if parts[0] != "CVSS:3.1":
        raise CVSSValidationError(f"Invalid CVSS prefix '{parts[0]}'. Vector must start with 'CVSS:3.1'.")

    metric_parts = parts[1:]
    if len(metric_parts) != len(REQUIRED_METRIC_KEYS):
        raise CVSSValidationError(
            f"Expected {len(REQUIRED_METRIC_KEYS)} base metrics, found {len(metric_parts)}."
        )

    metrics: Dict[str, str] = {}
    for part in metric_parts:
        if ":" not in part:
            raise CVSSValidationError(f"Invalid metric token '{part}'. Expected 'KEY:VALUE' format.")
        k, v = part.split(":", 1)
        k, v = k.strip().upper(), v.strip().upper()

        if k not in VALID_METRICS:
            raise CVSSValidationError(f"Unknown CVSS base metric key '{k}'.")
        if k in metrics:
            raise CVSSValidationError(f"Duplicate CVSS metric key '{k}' in vector.")
        if v not in VALID_METRICS[k]:
            valid_vals = ", ".join(VALID_METRICS[k])
            raise CVSSValidationError(f"Invalid value '{v}' for metric '{k}'. Must be one of: {valid_vals}.")

        metrics[k] = v

    for req_k in REQUIRED_METRIC_KEYS:
        if req_k not in metrics:
            raise CVSSValidationError(f"Missing required CVSS metric '{req_k}'.")

    return metrics


def calculate_base_score(metrics: Dict[str, str]) -> float:
    """Calculate the official CVSS v3.1 Base Score from validated metrics."""
    av = AV_WEIGHTS[metrics["AV"]]
    ac = AC_WEIGHTS[metrics["AC"]]
    ui = UI_WEIGHTS[metrics["UI"]]
    scope = metrics["S"]
    pr = PR_WEIGHTS[scope][metrics["PR"]]

    c = CIA_WEIGHTS[metrics["C"]]
    i = CIA_WEIGHTS[metrics["I"]]
    a = CIA_WEIGHTS[metrics["A"]]

    # Impact Sub-Score (ISS)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # Impact
    if scope == "U":
        impact = 6.42 * iss
    else:  # Scope Changed
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score calculation
    if impact <= 0:
        return 0.0

    if scope == "U":
        return roundup(min(impact + exploitability, 10.0))
    else:
        return roundup(min(1.08 * (impact + exploitability), 10.0))


def score_to_severity(score: float) -> str:
    """Map a CVSS v3.1 base score to a standard PenRepGen severity rating."""
    if score == 0.0:
        return "Info"
    elif 0.1 <= score <= 3.9:
        return "Low"
    elif 4.0 <= score <= 6.9:
        return "Medium"
    elif 7.0 <= score <= 8.9:
        return "High"
    elif 9.0 <= score <= 10.0:
        return "Critical"
    else:
        raise ValueError(f"Score {score} is out of the valid CVSS range [0.0, 10.0].")


def score_vector(vector_str: str) -> Tuple[float, str]:
    """Parse a CVSS v3.1 vector string, calculate its base score and severity rating."""
    metrics = parse_vector(vector_str)
    score = calculate_base_score(metrics)
    severity = score_to_severity(score)
    return score, severity
