"""``scripts/threatmodel_check.py`` fails on exactly the defects it is there to catch, and passes on the repository."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import threatmodel_check as tm  # noqa: E402

ROW = "| {cat} | threat | mitigation `src/a.py` | `tests/t.py` | none known |"


def _doc(rows: list[str] | None = None, drop_section: str | None = None) -> str:
    rows = rows if rows is not None else [ROW.format(cat=c) for c in tm.CATEGORIES]
    secs = [s for s in tm.SECTIONS if s != "## STRIDE" and s != drop_section]
    body = "\n\n".join(f"{s}\ntext" for s in secs)
    table = (
        "| Category | Threat | Mitigation | Test | Residual |\n| --- | --- | --- | --- | --- |\n"
        + "\n".join(rows)
    )
    return body + "\n\n## STRIDE\n\n" + table + "\n"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "docs" / "security").mkdir(parents=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "a.py").write_text("")
    (tmp_path / "tests" / "t.py").write_text("")
    (tmp_path / "docs" / "NEEDS.md").write_text("| 7 | x | y |\n")
    (tmp_path / "docs" / "security" / "README.md").write_text("stride-x.md")
    return tmp_path


def _write(root: Path, text: str) -> list[str]:
    (root / "docs" / "security" / "stride-x.md").write_text(text)
    return tm.check(root, ["x"])


def test_the_repository_passes() -> None:
    assert tm.check() == []


def test_a_valid_file_passes(root: Path) -> None:
    assert _write(root, _doc()) == []


def test_a_missing_component_file_fails(root: Path) -> None:
    assert any("has no docs/security/stride-y.md" in e for e in tm.check(root, ["y"]))


def test_a_missing_section_fails(root: Path) -> None:
    errs = _write(root, _doc(drop_section="## Prompt injection"))
    assert any("missing section '## Prompt injection'" in e for e in errs)


def test_an_empty_stride_category_fails(root: Path) -> None:
    rows = [ROW.format(cat=c) for c in tm.CATEGORIES if c != "Repudiation"]
    assert any("no Repudiation row" in e for e in _write(root, _doc(rows)))


def test_a_cited_path_that_does_not_exist_fails(root: Path) -> None:
    bad = "| Spoofing | t | m `src/missing.py` | `tests/t.py` | none known |"
    rows = [bad] + [ROW.format(cat=c) for c in tm.CATEGORIES[1:]]
    assert any("cited path does not exist: src/missing.py" in e for e in _write(root, _doc(rows)))


def test_a_cited_test_that_does_not_exist_fails(root: Path) -> None:
    bad = "| Spoofing | t | m `src/a.py` | `tests/nope.py` | none known |"
    rows = [bad] + [ROW.format(cat=c) for c in tm.CATEGORIES[1:]]
    assert any("tests/nope.py" in e for e in _write(root, _doc(rows)))


def test_a_needs_id_that_does_not_exist_fails_and_one_that_does_passes(root: Path) -> None:
    bad = "| Spoofing | t | m `src/a.py` | `tests/t.py` | open (NEEDS #99) |"
    good = "| Spoofing | t | m `src/a.py` | `tests/t.py` | open (NEEDS #7) |"
    rest = [ROW.format(cat=c) for c in tm.CATEGORIES[1:]]
    assert any("NEEDS #99" in e for e in _write(root, _doc([bad, *rest])))
    assert _write(root, _doc([good, *rest])) == []


def test_a_row_with_no_test_needs_a_needs_reference(root: Path) -> None:
    rest = [ROW.format(cat=c) for c in tm.CATEGORIES[1:]]
    untested = "| Spoofing | t | m `src/a.py` | none | accepted |"
    assert any("no test and no NEEDS" in e for e in _write(root, _doc([untested, *rest])))
    ok = "| Spoofing | t | m `src/a.py` | none | open (NEEDS #7) |"
    assert _write(root, _doc([ok, *rest])) == []


def test_a_mitigation_without_a_code_path_fails(root: Path) -> None:
    rest = [ROW.format(cat=c) for c in tm.CATEGORIES[1:]]
    bare = "| Spoofing | t | only words | `tests/t.py` | none known |"
    assert any("no code path" in e for e in _write(root, _doc([bare, *rest])))


def test_an_unindexed_file_fails(root: Path) -> None:
    (root / "docs" / "security" / "README.md").write_text("nothing")
    assert any("README.md does not index stride-x.md" in e for e in _write(root, _doc()))
