"""YAML data loader and validator for penetration test findings."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional, Union
import yaml

from penrepgen.cvss import CVSSValidationError, score_vector

SEVERITY_ORDER: Dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}

VALID_SEVERITIES: Dict[str, str] = {s.lower(): s for s in SEVERITY_ORDER}
VALID_SEVERITIES["none"] = "Info"

REQUIRED_ENGAGEMENT_FIELDS = ("title", "client", "tester", "date", "scope")
REQUIRED_FINDING_FIELDS = ("id", "title", "host", "description", "remediation")


class ValidationError(Exception):
    """Raised when the report YAML data fails validation."""


def _validate_engagement(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate engagement section and required fields."""
    if "engagement" not in data or not isinstance(data["engagement"], dict):
        raise ValidationError("Missing or invalid 'engagement' section in YAML.")

    engagement: Dict[str, Any] = data["engagement"]
    for field in REQUIRED_ENGAGEMENT_FIELDS:
        val = engagement.get(field)
        if val is None or (isinstance(val, str) and not val.strip()) or (isinstance(val, list) and len(val) == 0):
            raise ValidationError(f"Engagement is missing required field '{field}'.")

    # Ensure scope is normalized as a list of strings
    raw_scope = engagement["scope"]
    if isinstance(raw_scope, str):
        engagement["scope"] = [raw_scope.strip()]
    elif isinstance(raw_scope, list):
        engagement["scope"] = [str(item).strip() for item in raw_scope if str(item).strip()]
        if not engagement["scope"]:
            raise ValidationError("Engagement field 'scope' must not be empty.")
    else:
        raise ValidationError("Engagement field 'scope' must be a list or string.")

    return engagement


def _validate_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate findings list, normalize severity, and ensure unique IDs."""
    if "findings" not in data or not isinstance(data["findings"], list):
        raise ValidationError("Missing or invalid 'findings' section in YAML.")

    seen_ids = set()
    validated_findings: List[Dict[str, Any]] = []

    for idx, raw_finding in enumerate(data["findings"]):
        if not isinstance(raw_finding, dict):
            raise ValidationError(f"Finding at index {idx + 1} is not a valid mapping.")

        finding_id = raw_finding.get("id")
        if not finding_id or not str(finding_id).strip():
            raise ValidationError(f"Finding at index {idx + 1} is missing required field 'id'.")

        finding_id_str = str(finding_id).strip()
        if finding_id_str in seen_ids:
            raise ValidationError(f"Duplicate finding ID '{finding_id_str}' found.")
        seen_ids.add(finding_id_str)

        # Check all required base finding fields
        for field in REQUIRED_FINDING_FIELDS:
            val = raw_finding.get(field)
            if val is None or (isinstance(val, str) and not val.strip()):
                raise ValidationError(f"Finding '{finding_id_str}' is missing required field '{field}'.")

        # Parse optional CVSS vector if present
        raw_vector = raw_finding.get("cvss_vector")
        cvss_vector_clean: Optional[str] = None
        cvss_score: Optional[float] = None
        calc_sev: Optional[str] = None

        if raw_vector is not None and str(raw_vector).strip():
            cvss_vector_clean = str(raw_vector).strip()
            try:
                calc_score, calc_sev = score_vector(cvss_vector_clean)
                cvss_score = calc_score
            except CVSSValidationError as err:
                raise ValidationError(f"Finding '{finding_id_str}' has invalid cvss_vector: {err}")

        # Validate severity and resolve relationship with CVSS vector
        raw_sev = raw_finding.get("severity")
        has_raw_sev = raw_sev is not None and str(raw_sev).strip()

        if has_raw_sev:
            raw_sev_str = str(raw_sev).strip().lower()
            if raw_sev_str not in VALID_SEVERITIES:
                valid_list = ", ".join(SEVERITY_ORDER.keys())
                raise ValidationError(
                    f"Finding '{finding_id_str}' has invalid severity '{raw_finding['severity']}'. "
                    f"Must be one of: {valid_list}."
                )
            explicit_sev = VALID_SEVERITIES[raw_sev_str]
            if calc_sev is not None:
                if explicit_sev != calc_sev:
                    sys.stderr.write(
                        f"Warning: Finding '{finding_id_str}' specified severity '{explicit_sev}' "
                        f"but CVSS vector calculates to '{calc_sev}'. Using '{calc_sev}'.\n"
                    )
                final_sev = calc_sev
            else:
                final_sev = explicit_sev
        else:
            if calc_sev is not None:
                final_sev = calc_sev
            else:
                raise ValidationError(
                    f"Finding '{finding_id_str}' is missing required field 'severity' (or 'cvss_vector')."
                )

        # Normalize optional fields
        evidence = raw_finding.get("evidence")
        if evidence is None:
            evidence_str = ""
        else:
            evidence_str = str(evidence)

        raw_refs = raw_finding.get("references")
        if raw_refs is None:
            references: List[str] = []
        elif isinstance(raw_refs, list):
            references = [str(r).strip() for r in raw_refs if str(r).strip()]
        elif isinstance(raw_refs, str):
            references = [raw_refs.strip()] if raw_refs.strip() else []
        else:
            references = [str(raw_refs)]

        finding_item: Dict[str, Any] = {
            "id": finding_id_str,
            "title": str(raw_finding["title"]).strip(),
            "severity": final_sev,
            "cvss_vector": cvss_vector_clean,
            "cvss_score": cvss_score,
            "host": str(raw_finding["host"]).strip(),
            "description": str(raw_finding["description"]).strip(),
            "evidence": evidence_str,
            "remediation": str(raw_finding["remediation"]).strip(),
            "references": references,
        }
        validated_findings.append(finding_item)

    # Sort findings: severity rank first, then CVSS score descending within the same severity
    validated_findings.sort(
        key=lambda f: (
            SEVERITY_ORDER[f["severity"]],
            0 if f["cvss_score"] is not None else 1,
            -(f["cvss_score"] if f["cvss_score"] is not None else 0.0),
        )
    )
    return validated_findings


def _calculate_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate summary count for each severity and highest CVSS score."""
    summary: Dict[str, Any] = {sev: 0 for sev in SEVERITY_ORDER.keys()}
    for f in findings:
        sev = f["severity"]
        summary[sev] = summary.get(sev, 0) + 1

    scores = [f["cvss_score"] for f in findings if f.get("cvss_score") is not None]
    highest_cvss = max(scores) if scores else None
    summary["highest_cvss"] = highest_cvss
    summary["Highest CVSS"] = highest_cvss
    return summary


def load_findings(source: Union[str, os.PathLike]) -> Dict[str, Any]:
    """Load and validate findings from a YAML file.

    Args:
        source: File path to the YAML input.

    Returns:
        Dict containing validated 'engagement', sorted 'findings', and 'summary'.

    Raises:
        ValidationError: If the YAML is invalid or violates schema requirements.
    """
    file_path = str(source)
    if not os.path.exists(file_path):
        raise ValidationError(f"File not found: '{file_path}'.")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except yaml.YAMLError as err:
        raise ValidationError(f"YAML parsing error in '{file_path}': {err}")
    except OSError as err:
        raise ValidationError(f"Failed to read file '{file_path}': {err}")

    if not isinstance(raw_data, dict):
        raise ValidationError(f"YAML document in '{file_path}' must be a key-value mapping.")

    engagement = _validate_engagement(raw_data)
    findings = _validate_findings(raw_data)
    summary = _calculate_summary(findings)

    return {
        "engagement": engagement,
        "findings": findings,
        "summary": summary,
    }
