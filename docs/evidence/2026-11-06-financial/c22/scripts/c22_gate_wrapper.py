"""Run a 5 Nov gate script against C22 (2.2.13). Copy of c21_gate_wrapper.py: the C22 harness no longer pins the
version (it checks the package against the installed one), so the only in-memory change is lab_thursday.py's
financial package-hash pin C18 -> C22 (dist/v2213-c22-candidates/SHA256SUMS). No repo/VM file edits."""
import sys
from pathlib import Path

gate, edition, package, source = sys.argv[1:5]
sys.path.insert(0, str(Path(source, "testing")))
code = Path(gate).read_text()
if Path(gate).name == "lab_thursday.py":
    c18, c22 = "6e4f812567e87ffb6c8b26e7bbd4d5bc797055e7dfcbf5ab759e4fcc8289e08f", "6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9"
    assert code.count(c18) == 1
    code = code.replace(c18, c22)
print("WRAPPER in-memory overrides:", "financial package hash pin C18->C22" if Path(gate).name == "lab_thursday.py" else "none", flush=True)
sys.argv = [gate, edition, package, source]
exec(compile(code, gate, "exec"), {"__name__": "__main__", "__file__": gate})
