"""Tests for regular-expression denial-of-service detection."""

from pathlib import Path

import pytest

from argus_languages.scanner import scan_path

@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("unsafe.py", 're.compile(request.args["pattern"])'),
        ("unsafe.py", "re.compile(req.query.pattern)"),
        ("unsafe.py", "re.compile(input())"),
        ("unsafe.js", "const pattern = new RegExp(req.query.q);"),
        ("unsafe.ts", "const pattern = new RegExp(request.body.pattern);"),
        ("unsafe.java", 'Pattern.compile(request.getParameter("re"));'),
    ],
)
def test_redos_user_controlled_patterns_flagged(tmp_path: Path, filename: str, source: str):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert "redos-user-controlled-pattern" in {
        finding.rule_id for finding in scan_path(f).findings
    }


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("unsafe.py", 're.compile(r"(a+)+$")'),
        ("unsafe.py", 're.compile(r"A(B|C+)+D")'),
        ("unsafe.py", 're.compile(r"(a|aa)+$")'),
        ("unsafe.py", 're.compile(r"(.*a){5}$")'),
        ("unsafe.py", 're.compile(r"(\\[[^\\[\\]]*\\]|\\s+)+")'),
        ("unsafe.py", 're.compile(r"^((?:\\d+)?\\.?\\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|years?|yrs?|y)?$", re.I)'),
        ("unsafe.py", 're.compile(r"(x|x)*$")'),
        ("unsafe.js", 'const pattern = new RegExp("(a+)+$");'),
        ("unsafe.java", 'Pattern pattern = Pattern.compile("(a+)+$");'),
    ],
)
def test_redos_catastrophic_literal_patterns_flagged(
    tmp_path: Path, filename: str, source: str
):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert "redos-catastrophic-pattern" in {
        finding.rule_id for finding in scan_path(f).findings
    }


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("safe.py", 're.compile(re.escape(request.args["pattern"]))'),
        ("safe.py", 're2.compile(request.args["pattern"])'),
        ("safe.py", 're.compile(r"^\\d{4}-\\d{2}-\\d{2}$")'),
        ("safe.py", 're.compile(r"(cat|dog)+$")'),
        ("safe.js", 'const pattern = new RegExp("^(cat|dog)+$");'),
        ("safe.java", 'Pattern pattern = Pattern.compile("^(cat|dog)+$");'),
        ("safe.js", "const pattern = new RegExp(escapeRegExp(req.query.q));"),
        ("safe.java", 'Pattern.compile(Pattern.quote(request.getParameter("re")));'),
    ],
)
def test_redos_safe_patterns_not_flagged(tmp_path: Path, filename: str, source: str):
    f = tmp_path / filename
    f.write_text(source + "\n")
    assert not {
        finding.rule_id
        for finding in scan_path(f).findings
        if finding.rule_id.startswith("redos-")
    }
