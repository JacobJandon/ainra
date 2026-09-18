# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The version a user reads at runtime must equal the version they installed.

Not a style rule. `ainra 0.4.0` shipped to PyPI reporting ``__version__ == "0.3.0"``: the wheel metadata and
the module disagreed, and a published artifact cannot be edited afterwards — only superseded. Two strings for
one fact will drift again unless something fails when they do. This is that something.
"""

import re
from pathlib import Path

import ainra

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _declared_version() -> str:
    """The packaging version, read from the manifest that builds the wheel."""
    text = PYPROJECT.read_text(encoding="utf-8")
    try:  # tomllib is 3.11+; requires-python is >=3.10, so fall back rather than skip the check
        import tomllib

        return tomllib.loads(text)["project"]["version"]
    except ModuleNotFoundError:
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert match, "pyproject.toml declares no [project] version"
        return match.group(1)


def test_module_version_matches_pyproject():
    assert ainra.__version__ == _declared_version(), (
        f"ainra.__version__ is {ainra.__version__!r} but pyproject.toml declares "
        f"{_declared_version()!r} — the installed package would report the wrong version"
    )
