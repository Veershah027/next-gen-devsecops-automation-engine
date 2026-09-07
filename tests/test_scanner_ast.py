"""AST structural scanner (parsed, never executed)."""

from __future__ import annotations

from models import FindingCategory, Severity
from scanner import ast_scan


def _scan(src: str):
    return ast_scan(src, "ast_structural_parser", lambda *p: "id:" + "|".join(map(str, p)))


def _categories(src: str) -> set[FindingCategory]:
    return {f.category for f in _scan(src)}


def test_syntax_error_reported() -> None:
    findings = _scan("def broken(:\n    pass\n")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.SYNTAX
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].position is not None


def test_clean_code_yields_nothing() -> None:
    assert _scan("def f(a, b):\n    return a + b\n") == []


def test_triple_nested_loop_flagged() -> None:
    src = "for a in x:\n    for b in y:\n        for c in z:\n            pass\n"
    perf = [f for f in _scan(src) if f.category is FindingCategory.PERFORMANCE]
    assert perf and "3-level" in perf[0].title


def test_double_nested_loop_not_flagged() -> None:
    src = "for a in x:\n    for b in y:\n        pass\n"
    assert FindingCategory.PERFORMANCE not in _categories(src)


def test_four_level_loop_is_high_severity() -> None:
    src = "for a in w:\n for b in x:\n  for c in y:\n   for d in z:\n    pass\n"
    perf = [f for f in _scan(src) if f.category is FindingCategory.PERFORMANCE]
    assert perf[0].severity is Severity.HIGH


def test_eval_flagged() -> None:
    assert FindingCategory.DANGEROUS_CALL in _categories("y = eval(user_input)\n")


def test_exec_flagged() -> None:
    assert FindingCategory.DANGEROUS_CALL in _categories("exec(code_string)\n")


def test_compile_flagged() -> None:
    assert FindingCategory.DANGEROUS_CALL in _categories("compile(src, 'f', 'exec')\n")


def test_dunder_import_flagged() -> None:
    assert FindingCategory.DANGEROUS_CALL in _categories("m = __import__(name)\n")


def test_normal_function_calls_not_flagged() -> None:
    assert FindingCategory.DANGEROUS_CALL not in _categories("print('hi')\nlen([1, 2])\njson.loads(s)\n")


def test_bare_except_flagged() -> None:
    src = "try:\n    risky()\nexcept:\n    pass\n"
    style = [f for f in _scan(src) if f.category is FindingCategory.STYLE]
    assert any("except" in f.title.lower() for f in style)


def test_typed_except_not_flagged() -> None:
    src = "try:\n    risky()\nexcept ValueError:\n    pass\n"
    assert FindingCategory.STYLE not in _categories(src)


def test_mutable_default_list_flagged() -> None:
    src = "def f(items=[]):\n    return items\n"
    assert any("mutable default" in f.title.lower() for f in _scan(src))


def test_mutable_default_dict_flagged() -> None:
    assert any("mutable default" in f.title.lower() for f in _scan("def f(cache={}):\n    return cache\n"))


def test_none_default_not_flagged() -> None:
    src = "def f(items=None):\n    return items or []\n"
    assert FindingCategory.STYLE not in _categories(src)


def test_findings_are_deterministic() -> None:
    src = "eval(x)\nfor a in p:\n for b in q:\n  for c in r:\n   pass\n"
    first = [f.id for f in _scan(src)]
    second = [f.id for f in _scan(src)]
    assert first == second
