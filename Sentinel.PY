#!/usr/bin/env python3
"""Offline static security checks for source code and configuration files."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence


SEVERITIES = ("critical", "high", "medium", "low")
DEFAULT_EXCLUDES = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
)
SCANNABLE_SUFFIXES = {
    ".bat",
    ".c",
    ".cfg",
    ".conf",
    ".cc",
    ".cmd",
    ".cpp",
    ".cs",
    ".dart",
    ".gradle",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".m",
    ".mm",
    ".php",
    ".pem",
    ".ps1",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
SCANNABLE_NAMES = {
    "dockerfile",
    "makefile",
    "procfile",
    ".env",
    ".env.local",
    ".env.production",
}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    recommendation: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    path: str
    line: int
    recommendation: str


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    errors: list[str]


def make_rules() -> tuple[Rule, ...]:
    definitions = (
        (
            "PRIVATE-KEY",
            "critical",
            "Private key material in a file",
            "Remove the key, rotate it, and use a secrets manager or protected key store.",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        ),
        (
            "HARDCODED-SECRET",
            "high",
            "Possible hard-coded credential or API token",
            "Remove the value, rotate the credential, and load it from a secrets manager.",
            r"""(?ix)
            \b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|
            password|passwd|secret|token)\b
            \s*[:=]\s*["']?
            (?!["']?\s*(?:$|none\b|null\b|undefined\b|your[_ -]|example\b|
            changeme\b|placeholder\b|<))
            [A-Za-z0-9_./+=:@-]{8,}
            """,
        ),
        (
            "AWS-ACCESS-KEY",
            "high",
            "Possible AWS access key ID",
            "Revoke the key and use an IAM role or short-lived credentials.",
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        ),
        (
            "COMMAND-INJECTION",
            "high",
            "Shell command execution with shell enabled",
            "Avoid shell execution; pass an argument list and validate untrusted input.",
            r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)\n]*\bshell\s*=\s*True",
        ),
        (
            "OS-SYSTEM",
            "high",
            "Direct shell command execution",
            "Avoid os.system; use a subprocess argument list with validated input.",
            r"\bos\.system\s*\(",
        ),
        (
            "DYNAMIC-EVAL",
            "high",
            "Dynamic code evaluation",
            "Avoid eval/exec on input that may be influenced by an untrusted source.",
            r"\b(?:eval|exec)\s*\(",
        ),
        (
            "SQL-STRING-FORMAT",
            "high",
            "SQL execution may use interpolated or concatenated input",
            "Use parameterized queries and bind values separately from SQL text.",
            r"""(?ix)
            \b(?:execute|executemany|raw|query)\s*\(
            \s*(?:f["']|["'][^"']*%s|["'][^"']*["']\s*%|["'][^"']*["']\s*\+)
            """,
        ),
        (
            "TLS-VERIFY-DISABLED",
            "high",
            "TLS certificate verification disabled",
            "Enable certificate verification; do not use this setting in production.",
            r"\b(?:verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False)\b",
        ),
        (
            "UNSAFE-PICKLE",
            "high",
            "Unsafe deserialization with pickle",
            "Do not deserialize untrusted data with pickle; use a safe data format.",
            r"\bpickle\.(?:load|loads)\s*\(",
        ),
        (
            "UNSAFE-YAML",
            "high",
            "Potentially unsafe YAML deserialization",
            "Use yaml.safe_load for data that is not fully trusted.",
            r"\byaml\.load\s*\(",
        ),
        (
            "DEBUG-ENABLED",
            "medium",
            "Debug mode may be enabled",
            "Disable debug mode in deployed environments.",
            r"(?i)\b(?:debug\s*[:=]\s*True|DEBUG\s*=\s*True)\b",
        ),
        (
            "WEAK-HASH",
            "medium",
            "Weak hash algorithm used",
            "Use a modern hash such as SHA-256; use a password-hashing algorithm for passwords.",
            r"\b(?:hashlib\.(?:md5|sha1)\s*\(|(?:MD5|SHA1)\s*\()",
        ),
        (
            "OPEN-CORS",
            "medium",
            "Wildcard CORS origin",
            "Restrict allowed origins to the specific trusted domains that need access.",
            r"""(?i)(?:Access-Control-Allow-Origin\s*[:=]\s*["']?\*|CORS_ORIGIN\s*[:=]\s*["']\*)""",
        ),
    )
    return tuple(
        Rule(rule_id, severity, title, recommendation, re.compile(pattern))
        for rule_id, severity, title, recommendation, pattern in definitions
    )


RULES = make_rules()


def is_scannable(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in SCANNABLE_NAMES
        or (name.startswith(".env.") and len(name) > len(".env."))
        or path.suffix.lower() in SCANNABLE_SUFFIXES
    )


def walk_files(
    target: Path,
    excludes: Sequence[str],
    onerror: Callable[[OSError], None] | None = None,
) -> Iterator[Path]:
    if target.is_file():
        if is_scannable(target):
            yield target
        return

    for root, dirs, files in os.walk(target, followlinks=False, onerror=onerror):
        root_path = Path(root)
        relative_root = root_path.relative_to(target)
        dirs[:] = [
            name
            for name in dirs
            if not (root_path / name).is_symlink()
            and not any(
                fnmatch.fnmatch(name, pattern)
                or fnmatch.fnmatch((relative_root / name).as_posix(), pattern)
                for pattern in excludes
            )
        ]
        for name in files:
            path = root_path / name
            if path.is_symlink() or not is_scannable(path):
                continue
            relative_path = path.relative_to(target).as_posix()
            if not any(fnmatch.fnmatch(relative_path, pattern) for pattern in excludes):
                yield path


def scan_file(
    path: Path, display_path: str, max_size: int
) -> tuple[list[Finding], str | None]:
    try:
        if path.stat().st_size > max_size:
            return [], f"{display_path}: skipped (larger than {max_size} bytes)"
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return [], f"{display_path}: could not read file ({error})"

    if "\0" in content:
        return [], f"{display_path}: skipped (binary file)"

    findings: list[Finding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule in RULES:
            if rule.pattern.search(line):
                if rule.id == "UNSAFE-YAML" and re.search(
                    r"\bLoader\s*=\s*(?:yaml\.)?SafeLoader\b", line
                ):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        title=rule.title,
                        path=display_path,
                        line=line_number,
                        recommendation=rule.recommendation,
                    )
                )
    return findings, None


def scan(target: Path, excludes: Sequence[str], max_size: int) -> ScanResult:
    findings: list[Finding] = []
    errors: list[str] = []
    files_scanned = 0

    def record_walk_error(error: OSError) -> None:
        errors.append(f"{error.filename or target}: could not scan directory ({error})")

    for path in walk_files(target, excludes, onerror=record_walk_error):
        try:
            display_path = (
                path.relative_to(target).as_posix() if target.is_dir() else path.name
            )
        except ValueError:
            display_path = path.as_posix()
        file_findings, error = scan_file(path, display_path, max_size)
        if error:
            errors.append(error)
            continue
        files_scanned += 1
        findings.extend(file_findings)
    findings.sort(key=lambda item: (SEVERITIES.index(item.severity), item.path, item.line, item.rule_id))
    return ScanResult(findings, files_scanned, errors)


def render_text(result: ScanResult) -> str:
    lines: list[str] = []
    if result.findings:
        for finding in result.findings:
            lines.append(
                f"{finding.severity.upper():8} {finding.path}:{finding.line} "
                f"[{finding.rule_id}] {finding.title}"
            )
            lines.append(f"         Recommendation: {finding.recommendation}")
    else:
        lines.append("No findings.")
    lines.append(f"\nScanned {result.files_scanned} file(s); found {len(result.findings)} issue(s).")
    if result.errors:
        lines.append("\nScan warnings:")
        lines.extend(f"- {error}" for error in result.errors)
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan source code and configuration for common security risks (offline static checks)."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--severity",
        choices=SEVERITIES,
        default="low",
        help="Minimum severity that causes exit status 1 (default: low)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Exclude a path/name glob; may be supplied more than once",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        metavar="BYTES",
        help="Skip files larger than this size (default: 1000000)",
    )
    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        parser.error(f"path does not exist: {target}")
    if target.is_symlink():
        parser.error("refusing to scan a symbolic link")
    if not target.is_file() and not target.is_dir():
        parser.error(f"path is not a regular file or directory: {target}")
    if target.is_file() and not is_scannable(target):
        parser.error(f"unsupported file type: {target}")
    if args.max_file_size <= 0:
        parser.error("--max-file-size must be greater than zero")

    result = scan(target, (*DEFAULT_EXCLUDES, *args.exclude), args.max_file_size)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "files_scanned": result.files_scanned,
                    "finding_count": len(result.findings),
                    "findings": [asdict(finding) for finding in result.findings],
                    "errors": result.errors,
                },
                indent=2,
            )
        )
    else:
        print(render_text(result))

    threshold = SEVERITIES.index(args.severity)
    has_blocking_finding = any(
        SEVERITIES.index(item.severity) <= threshold for item in result.findings
    )
    if result.errors:
        return 2
    return 1 if has_blocking_finding else 0


if __name__ == "__main__":
    sys.exit(main())
