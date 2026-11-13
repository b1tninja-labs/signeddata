"""signeddata declares one runtime dependency, asn1core, and imports nothing third-party."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_package_imports_with_asn1crypto_blocked():
    code = (
        "import sys\n"
        "for name in ('asn1crypto', 'cryptography', 'pyasn1'):\n"
        "    sys.modules[name] = None\n"
        f"sys.path[:0] = [{str(ROOT)!r}, {str(ROOT.parent / 'asn1core')!r}]\n"
        "import signeddata\n"
        "from signeddata import cms\n"
        "assert callable(cms.load)\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_pyproject_dependencies_are_only_asn1core():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == ["asn1core"]


def test_package_source_names_no_third_party_import():
    banned = ("asn1crypto", "pyasn1", "cryptography")
    for path in (ROOT / "signeddata").rglob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                assert not any(stripped.split()[1].split(".")[0] == b for b in banned), path
