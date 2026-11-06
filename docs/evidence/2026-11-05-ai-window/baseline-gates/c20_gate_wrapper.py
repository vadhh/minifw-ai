"""Run a morning gate script against C20 with ONE in-memory harness override (no repo/VM file edits)."""
import sys, types
from pathlib import Path

gate, edition, package, source = sys.argv[1:5]
testing = Path(source, "testing")
sys.path.insert(0, str(testing))
path = testing / "lab_gateway_acceptance.py"
text = path.read_text()
old = 'assert installed == "2.2.10-" + sector, "Only v2.2.10 may be tested"'
assert text.count(old) == 1
text = text.replace(old, 'assert installed == "2.2.11-" + sector, "Only v2.2.11 may be tested"')
module = types.ModuleType("lab_gateway_acceptance")
module.__file__ = str(path)
sys.modules[module.__name__] = module
exec(compile(text, str(path), "exec"), module.__dict__)

code = Path(gate).read_text()
if Path(gate).name == "lab_thursday.py":
    # Package-identity pin: C18 hashes -> C20 hashes (dist/v2211-c20-candidates/SHA256SUMS).
    for c18, c20 in (("b180e835a9769ca9ca6de2f0932dd72f190a8a1fd2c13fe392d929353ad18843", "dae8ee0c343c0e2b3509b9264408c16057b9c5c9102115f37032fad11dbd262d"),
                     ("6e4f812567e87ffb6c8b26e7bbd4d5bc797055e7dfcbf5ab759e4fcc8289e08f", "ec3c1c21addefba89accd913379f0d84753203f4cdd1bba683f989419dbd3300")):
        assert code.count(c18) == 1
        code = code.replace(c18, c20)
print("WRAPPER in-memory overrides: harness version 2.2.10->2.2.11", "+ package hash pin C18->C20" if Path(gate).name == "lab_thursday.py" else "", flush=True)
sys.argv = [gate, edition, package, source]
exec(compile(code, gate, "exec"), {"__name__": "__main__", "__file__": gate})
