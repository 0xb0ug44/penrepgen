#!/usr/bin/env python3
"""Command-line interface for PenRepGen."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from penrepgen import __version__
from penrepgen.cvss import CVSSValidationError, score_vector
from penrepgen.loader import ValidationError, load_findings
from penrepgen.render import render_report


def determine_format(output_path: str, format_override: Optional[str]) -> str:
    """Determine the output format from explicit flag or file extension."""
    if format_override:
        fmt = format_override.lower().strip()
        if fmt in ("html", "md"):
            return fmt
        raise ValidationError(f"Invalid format '{format_override}'. Must be 'html' or 'md'.")

    ext = os.path.splitext(output_path)[1].lower()
    if ext in (".html", ".htm"):
        return "html"
    elif ext in (".md", ".markdown"):
        return "md"
    else:
        raise ValidationError(
            f"Cannot infer report format from output extension '{ext}'. "
            "Use an extension like .html or .md, or specify --format {html,md}."
        )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="penrepgen",
        description="Convert penetration test findings in YAML into client-ready HTML or Markdown reports, or score CVSS vectors.",
    )
    parser.add_argument(
        "-i",
        "--input",
        help="Path to the input YAML file containing engagement details and findings.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to the output report file (.html or .md).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["html", "md"],
        help="Explicitly override the output format (html or md).",
    )
    parser.add_argument(
        "--score",
        metavar="VECTOR",
        help="Calculate and print the CVSS v3.1 base score and severity for a vector string.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program version number and exit.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.score:
        try:
            score, severity = score_vector(args.score)
            print(f"{score} {severity}")
            return 0
        except CVSSValidationError as err:
            sys.stderr.write(f"Error: {err}\n")
            return 1
        except Exception as err:
            sys.stderr.write(f"Unexpected error: {err}\n")
            return 2

    if not args.input or not args.output:
        sys.stderr.write("Error: Both -i/--input and -o/--output are required when generating reports.\n")
        return 1

    try:
        report_format = determine_format(args.output, args.format)
        data = load_findings(args.input)
        rendered_content = render_report(data, report_format)

        output_dir = os.path.dirname(os.path.abspath(args.output))
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        with open(args.output, "w", encoding="utf-8") as f:
            f.write(rendered_content)

        print(f"[+] Successfully generated {report_format.upper()} report: {args.output}")
        return 0

    except ValidationError as err:
        sys.stderr.write(f"Error: {err}\n")
        return 1
    except Exception as err:
        sys.stderr.write(f"Unexpected error: {err}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
