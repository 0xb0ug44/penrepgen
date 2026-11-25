"""Template rendering engine for HTML and Markdown reports."""

from __future__ import annotations

import os
from typing import Any, Dict
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def _get_environment(autoescape: bool = True) -> Environment:
    """Create a configured Jinja2 Environment."""
    return Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(data: Dict[str, Any]) -> str:
    """Render the report data into a standalone HTML string with autoescape enabled."""
    env = _get_environment(autoescape=True)
    template = env.get_template("report.html.j2")
    return template.render(**data)


def render_markdown(data: Dict[str, Any]) -> str:
    """Render the report data into a GitHub-flavored Markdown string."""
    env = _get_environment(autoescape=False)
    template = env.get_template("report.md.j2")
    return template.render(**data)


def render_report(data: Dict[str, Any], format_name: str) -> str:
    """Render report in the specified format ('html' or 'md').

    Args:
        data: Validated report dictionary containing engagement, findings, and summary.
        format_name: Target output format ('html' or 'md').

    Returns:
        Rendered report as string.

    Raises:
        ValueError: If an unsupported format is requested.
    """
    normalized_format = format_name.lower().strip()
    if normalized_format == "html":
        return render_html(data)
    elif normalized_format in ("md", "markdown"):
        return render_markdown(data)
    else:
        raise ValueError(f"Unsupported report format: '{format_name}'. Supported formats: html, md.")
