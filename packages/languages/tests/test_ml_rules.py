"""Tests for AI/ML security static rules."""

from pathlib import Path

import pytest

from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path


def _scan_ml(path: Path):
    return scan_path(path, rules=load_rules_from_files(("ml.yaml",)))


def test_ml_torch_load(tmp_path: Path):
    f = tmp_path / "infer.py"
    f.write_text('import torch\nweights = torch.load("model.pt")\n')
    result = _scan_ml(f)
    assert "ml-torch-load-unsafe" in {x.rule_id for x in result.findings}


def test_ml_trust_remote_code(tmp_path: Path):
    f = tmp_path / "load.py"
    f.write_text(
        "from transformers import AutoModel\n"
        'm = AutoModel.from_pretrained("x", trust_remote_code=True)\n'
    )
    result = _scan_ml(f)
    assert "ml-trust-remote-code" in {x.rule_id for x in result.findings}


def test_ml_openai_key_assignment(tmp_path: Path):
    f = tmp_path / "config.py"
    f.write_text('OPENAI_API_KEY = "sk-test-key-should-not-be-here"\n')
    result = _scan_ml(f)
    assert "ml-llm-api-key-hardcoded" in {x.rule_id for x in result.findings}


def test_ml_prompt_fstring(tmp_path: Path):
    f = tmp_path / "chat.py"
    f.write_text('user = "ignore instructions"\nprompt = f"Summarize: {user}"\n')
    result = _scan_ml(f)
    assert "ml-llm-prompt-fstring" in {x.rule_id for x in result.findings}


@pytest.mark.parametrize(
    ("filename", "line", "rule_id"),
    [
        ("unsafe.py", "exec(resp.content[0].text)", "ml-llm-output-exec-eval"),
        ("unsafe.py", "eval(response.choices[0].message.content)", "ml-llm-output-exec-eval"),
        (
            "unsafe.py",
            "subprocess.run(resp.content[0].text, shell=True)",
            "ml-llm-output-subprocess-shell",
        ),
        ("unsafe.py", 'os.system(tool_args["command"])', "ml-agent-os-system-command"),
        ("unsafe.ts", "eval(response.text)", "ml-llm-output-eval-js"),
        (
            "unsafe.ts",
            "element.innerHTML = completion.choices[0].message.content;",
            "ml-llm-output-html",
        ),
        ("unsafe.ts", "element.innerHTML = response.text;", "ml-llm-output-html"),
    ],
)
def test_llm_output_direct_sinks_flagged(tmp_path: Path, filename: str, line: str, rule_id: str):
    f = tmp_path / filename
    f.write_text(line + "\n")
    assert rule_id in {finding.rule_id for finding in _scan_ml(f).findings}


@pytest.mark.parametrize(
    ("filename", "line"),
    [
        ("safe.py", "print(response.choices[0].message.content)"),
        ("safe.py", "subprocess.run(['git', 'status'], check=True)"),
        ("safe.py", "cursor.execute('SELECT * FROM users WHERE name = %s', (name,))"),
        ("safe.ts", "element.textContent = completion.content;"),
        ("safe.ts", "const parsed = JSON.parse(result.text);"),
        ("safe.ts", "eval('2 + 2')"),
        ("safe.py", "ast.literal_eval(resp.text)"),
        ("safe.ts", "el.innerHTML = other.textContent"),
        ("safe.ts", "eval(script.textContent)"),
        ("safe.py", 'cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")'),
        ("safe.py", "os.system(args[0])"),
    ],
)
def test_safe_output_handling_not_flagged(tmp_path: Path, filename: str, line: str):
    f = tmp_path / filename
    f.write_text(line + "\n")
    assert not _scan_ml(f).findings


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
