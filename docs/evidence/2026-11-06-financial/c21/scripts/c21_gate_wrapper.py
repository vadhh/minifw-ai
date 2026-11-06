"""Run a 5 Nov gate script against C21 (2.2.12). Copy of c20_gate_wrapper.py: the C21 harness no longer pins the
version (it checks the package against the installed one), so the only in-memory change is lab_thursday.py's
financial package-hash pin C18 -> C21 (dist/v2212-c21-candidates/SHA256SUMS). No repo/VM file edits."""
import sys
from pathlib import Path

gate, edition, package, source = sys.argv[1:5]
sys.path.insert(0, str(Path(source, "testing")))
code = Path(gate).read_text()
if Path(gate).name == "lab_thursday.py":
    c18, c21 = "6e4f812567e87ffb6c8b26e7bbd4d5bc797055e7dfcbf5ab759e4fcc8289e08f", "41c8345de1a8fd880bbbd36d6d91a3977137ed133f7e0ce7e215559ca7b2dd11"
    assert code.count(c18) == 1
    code = code.replace(c18, c21)
print("WRAPPER in-memory overrides:", "financial package hash pin C18->C21" if Path(gate).name == "lab_thursday.py" else "none", flush=True)
sys.argv = [gate, edition, package, source]
exec(compile(code, gate, "exec"), {"__name__": "__main__", "__file__": gate})
