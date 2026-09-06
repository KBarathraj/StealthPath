"""Streamlit must stay optional. This is the test that keeps it that way.

The dashboard is a demo; the suite is the evidence chain. Coupling the second to
the first would mean a reviewer cannot run the tests without installing a web
framework, so `streamlit` is a `[dashboard]` extra and is imported at call time
inside `dashboard.app` rather than at module scope.

That property is easy to break by accident — one top-level `import streamlit`
added later and the whole suite starts requiring it — and easy to check, so it
is checked rather than documented.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "dashboard"


def _module_level_imports(path: Path) -> set[str]:
    """Top-level import names only — not those nested inside a function."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:                      # module scope only
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("path", sorted(DASHBOARD.glob("*.py")),
                         ids=lambda p: p.name)
def test_no_dashboard_module_imports_streamlit_at_module_scope(path):
    """Including `app.py`, which is allowed to use it — but only inside a call."""
    assert "streamlit" not in _module_level_imports(path), (
        f"{path.name} imports streamlit at module scope. The suite must run "
        f"without it; import inside the function that needs it.")


def test_the_compute_layer_is_importable_without_streamlit():
    """Whatever is installed locally, these must not depend on it."""
    for mod in ("dashboard", "dashboard.compute", "dashboard.rl_view",
                "dashboard.figures"):
        __import__(mod)
    assert "dashboard.compute" in sys.modules


def test_importing_the_app_module_does_not_require_streamlit():
    """`import dashboard.app` must succeed on a machine without the extra.

    Only calling `main()` may need it. This is what lets the whole suite be
    collected on a bare checkout.
    """
    import dashboard.app as app

    assert app.main is not None
    assert "streamlit" not in _module_level_imports(DASHBOARD / "app.py")


def test_the_app_layer_holds_no_cost_model_or_planner_logic():
    """It renders what compute/rl_view return; it must not derive anything.

    A second derivation in a presentation layer is how a demo starts disagreeing
    with the paper, so the planners and the weight table are off-limits here.
    """
    src = (DASHBOARD / "app.py").read_text(encoding="utf-8")
    for banned in ("weight_of", "category_of", "static_cost_fn", "history_cost_fn",
                   "dijkstra", "astar", "exact_history_search", "PROVISIONAL_WEIGHTS",
                   "train("):
        assert banned not in src, (
            f"dashboard/app.py references {banned!r}. Rendering only — derive it "
            f"in dashboard.compute or dashboard.rl_view instead.")


def test_the_app_runs_as_a_script_not_only_as_a_module():
    """`streamlit run dashboard/app.py` executes the file top-level, not as a package.

    Regression test. `app.py` originally used relative imports (`from . import
    compute`), which import cleanly as `dashboard.app` and fail with "attempted
    relative import with no known parent package" under the actual entry point.
    Every import test above passed while the page was broken, because they all
    imported it the working way.
    """
    import subprocess

    src = (DASHBOARD / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, (
                f"app.py uses a relative import ({'.' * node.level}"
                f"{node.module or ''}) at module scope; it breaks under "
                f"`streamlit run`.")

    # Compile and execute the module body the way streamlit does: as __main__
    # with the file's own directory on sys.path, but WITHOUT the repo root.
    # main() is never called, so streamlit itself is not needed.
    probe = (
        "import sys, runpy, pathlib\n"
        f"p = pathlib.Path(r'{DASHBOARD / 'app.py'}')\n"
        "sys.path = [str(p.parent)] + [q for q in sys.path if q not in "
        f"(r'{ROOT}', '')]\n"
        "src = p.read_text(encoding='utf-8')\n"
        # Run the module body but not main(), which legitimately needs streamlit.
        # Both quote styles: matching only one silently let main() run, and the
        # test then failed for the wrong reason on a machine without the extra.
        "import re\n"
        "src, n = re.subn(r'if __name__ == .__main__.:', 'if False:', src)\n"
        "assert n == 1, f'expected one __main__ guard, found {n}'\n"
        "exec(compile(src, str(p), 'exec'), {'__name__': '__main__', "
        "'__file__': str(p)})\n"
        "print('OK')\n"
    )
    out = subprocess.run([sys.executable, "-c", probe],
                         capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0 and "OK" in out.stdout, (
        f"app.py fails when executed as a script:\n{out.stderr[-1500:]}")
