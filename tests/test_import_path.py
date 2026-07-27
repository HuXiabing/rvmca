from pathlib import Path

from rvmca.trans import prof


def test_prof_is_imported_from_this_checkout():
    repo_root = Path(__file__).resolve().parents[1]
    assert Path(prof.__file__).resolve().is_relative_to(repo_root / "src")
