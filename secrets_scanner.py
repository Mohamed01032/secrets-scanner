#!/usr/bin/env python3
"""secrets-scanner: find leaked credentials in a Git repository.

Scans the files in a working tree and, optionally, every line ever added in
the Git history. Standard library only.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

__version__ = "0.1.0"

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
IGNORE_FILE = ".secretsignore"
INLINE_IGNORE = "nosecret"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    pattern: "re.Pattern[str]"
    group: int = 0          # which regex group holds the secret itself
    min_entropy: float = 0  # 0 = no entropy check


def _r(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern)


RULES: list[Rule] = [
    Rule("aws-access-key", "AWS access key ID", "critical",
         _r(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    Rule("github-token", "GitHub token", "critical",
         _r(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), 1),
    Rule("google-api-key", "Google API key", "high",
         _r(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), 1),
    Rule("slack-token", "Slack token", "high",
         _r(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), 1),
    Rule("stripe-live-key", "Stripe live secret key", "critical",
         _r(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), 1),
    Rule("telegram-bot-token", "Telegram bot token", "high",
         _r(r"(?<![0-9A-Za-z])(\d{8,10}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])"), 1),
    Rule("anthropic-api-key", "Anthropic API key", "critical",
         _r(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), 1),
    Rule("openai-api-key", "OpenAI API key", "critical",
         _r(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{40,})"), 1),
    Rule("private-key", "Private key block", "critical",
         _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"), 1),
    Rule("jwt", "JSON Web Token", "medium",
         _r(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), 1),
    Rule("db-url-password", "Database URL with password", "high",
         _r(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:([^\s@/]{6,})@"), 1),
    Rule("generic-secret", "Hardcoded secret in assignment", "medium",
         _r(r"""(?ix)\b[\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|auth[_-]?key)[\w.-]*
                \s*[:=]\s*["']([^"'\s]{8,})["']"""), 1, 3.0),
]

PLACEHOLDER = re.compile(
    r"(?i)(example|sample|dummy|changeme|change_me|your[_-]|placeholder|x{4,}|\*{4,}|<.+>|\{[^}]*\}|%s|todo)"
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file: str
    line: int
    preview: str
    commit: Optional[str] = None


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random keys score high, words score low."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def redact(secret: str) -> str:
    """Never print a full secret: keep 4 characters and the length."""
    head = secret[:4]
    return f"{head}{'*' * 6} ({len(secret)} chars)"


def scan_line(line: str, file: str, lineno: int, commit: Optional[str] = None) -> list[Finding]:
    if INLINE_IGNORE in line:
        return []
    found: list[Finding] = []
    taken: list[tuple[int, int]] = []  # spans already matched by a specific rule
    for rule in RULES:
        for match in rule.pattern.finditer(line):
            secret = match.group(rule.group)
            span = match.span(rule.group)
            if rule.id == "generic-secret":
                if PLACEHOLDER.search(secret) or shannon_entropy(secret) < rule.min_entropy:
                    continue
                if any(s < span[1] and span[0] < e for s, e in taken):
                    continue  # a specific rule already reported this value
            taken.append(span)
            found.append(Finding(rule.id, rule.name, rule.severity, file, lineno, redact(secret), commit))
    return found


def scan_text(text: str, file: str, commit: Optional[str] = None) -> list[Finding]:
    found: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        found.extend(scan_line(line, file, lineno, commit))
    return found


def load_ignore(root: Path) -> list[str]:
    path = root / IGNORE_FILE
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def is_ignored(rel_path: str, patterns: Iterable[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(rel_path, pat.rstrip("/") + "/*"):
            return True
    return False


def _git(root: Path, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.decode("utf-8", errors="replace")


def list_files(root: Path) -> Iterator[Path]:
    """Tracked and untracked-but-not-ignored files in a Git repo, else every file."""
    listing = _git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if listing is not None:
        for rel in listing.split("\0"):
            if rel:
                yield root / rel
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def read_text_file(path: Path) -> Optional[str]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:2048]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def scan_tree(root: Path) -> list[Finding]:
    ignore = load_ignore(root)
    found: list[Finding] = []
    for path in list_files(root):
        rel = path.relative_to(root).as_posix()
        if rel == IGNORE_FILE or is_ignored(rel, ignore):
            continue
        text = read_text_file(path)
        if text is not None:
            found.extend(scan_text(text, rel))
    return found


HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_history(root: Path, max_commits: Optional[int] = None) -> list[Finding]:
    """Scan every line added in the Git history, including lines deleted later."""
    args = ["log", "-p", "--no-color", "--unified=0", "--format=commit %H"]
    if max_commits:
        args += ["-n", str(max_commits)]
    log = _git(root, *args)
    if log is None:
        raise RuntimeError("not a Git repository, or git is not installed")
    ignore = load_ignore(root)
    found: list[Finding] = []
    commit, file, lineno, skip = None, None, 0, False
    for line in log.splitlines():
        if line.startswith("commit "):
            commit, file = line[7:19], None
        elif line.startswith("+++ "):
            file = line[6:] if line.startswith("+++ b/") else None
            skip = file is None or is_ignored(file, ignore)
        elif line.startswith("@@"):
            m = HUNK.match(line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and file and not skip:
            found.extend(scan_line(line[1:], file, lineno, commit))
            lineno += 1
    return found


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule_id, f.file, f.preview, f.commit if f.commit else f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def format_text(findings: list[Finding], color: bool) -> str:
    if not findings:
        return "No secrets found."
    lines = []
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line)):
        sev = f.severity.upper().ljust(8)
        if color:
            sev = f"{COLORS[f.severity]}{sev}{RESET}"
        where = f"{f.file}:{f.line}" + (f" @ {f.commit}" if f.commit else "")
        lines.append(f"{sev} {f.rule_name}\n         {where}\n         {f.preview}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in sorted(counts, key=lambda s: -SEVERITY_ORDER[s]))
    lines.append(f"\n{len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="secrets-scanner", description="Find leaked credentials in a Git repository.")
    parser.add_argument("path", nargs="?", default=".", help="repository or folder to scan (default: current folder)")
    parser.add_argument("--history", action="store_true", help="also scan every line added in the Git history")
    parser.add_argument("--max-commits", type=int, help="limit the history scan to the newest N commits")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="low",
                        help="lowest severity that makes the exit code 1 (default: low)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {args.path} is not a folder", file=sys.stderr)
        return 2
    try:
        findings = scan_tree(root)
        if args.history:
            findings += scan_history(root, args.max_commits)
    except RuntimeError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    findings = dedupe(findings)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(format_text(findings, color=sys.stdout.isatty()))
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
