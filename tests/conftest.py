import sys
from pathlib import Path


REPO_SRC = str(Path(__file__).resolve().parents[1] / "src")
if REPO_SRC in sys.path:
    sys.path.remove(REPO_SRC)
sys.path.insert(0, REPO_SRC)
