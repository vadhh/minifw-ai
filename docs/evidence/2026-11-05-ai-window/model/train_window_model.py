"""Train and freeze client-window-v1 from the 5 November lab corpus (education + financial). Reproducible.

Usage (from the repo root):
  uv run --quiet --no-project --with scikit-learn==1.5.2 --with numpy==1.26.4 \
      python -I docs/evidence/2026-11-05-ai-window/model/train_window_model.py

Each edition is replayed separately through a fresh ClientWindow(ignore_before=0) (shared code in
evaluate_window_model.py); the n60 at each actor-labelled connection is one training row, human=0, tool=1.
Slow guessers are out of scope (D3): replayed and reported, never trained on. block_probability is fixed at 0.9
a priori. Stops without writing the model or manifest if any human client would be isolated on training data.
Refuses to overwrite a frozen model file with different bytes.
"""
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluate_window_model as ev  # noqa: E402  (also puts app/ on sys.path)
import numpy as np  # noqa: E402
import sklearn  # noqa: E402
from minifw_ai.client_window import FEATURES, SCHEMA, WindowModel  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402

CORPUS = ev.REPO / "docs/evidence/2026-11-05-ai-decision/corpus"
EDITIONS = ("education", "financial")
LABELS = {"human": 0, "tool": 1}
BLOCK_PROBABILITY = 0.9  # fixed a priori; not tuned
HYPERPARAMETERS = dict(C=1.0, class_weight=None, solver="lbfgs", max_iter=1000)  # sklearn defaults except max_iter
NOTE = "Lab-trained on a fictional sandbox corpus; scope fast password guessing only"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    inputs = sorted(p for e in EDITIONS for p in [*(CORPUS / e).glob("actor-*.jsonl"), CORPUS / e / "flows.jsonl.gz"])
    input_hashes = {str(p.relative_to(CORPUS)): sha256(p) for p in inputs}

    rows, data = [], {}
    for edition in EDITIONS:
        flows, stats = ev.replay(CORPUS / edition)
        actors, joined = ev.join(CORPUS / edition, flows)
        data[edition] = joined
        rows += [(f["n60"], LABELS[a["kind"]]) for a, f in joined if a["kind"] in LABELS]
    X = np.array([[n60] for n60, _ in rows], dtype=float)
    y = np.array([label for _, label in rows])
    clf = LogisticRegression(**HYPERPARAMETERS).fit(X, y)
    coef, intercept = float(clf.coef_[0][0]), float(clf.intercept_[0])

    trained_on = ("docs/evidence/2026-11-05-ai-decision/corpus/{education,financial} lab corpus (fictional sandbox, "
                  "8 clients per edition); n60 from ClientWindow(ignore_before=0) over deduped gateway flow exports, "
                  "actor-labelled connections human=0 tool=1, slow excluded; "
                  f"sklearn {sklearn.__version__} LogisticRegression(C=1.0, lbfgs, max_iter=1000), "
                  f"{len(rows)} rows; input sha256: " + ", ".join(f"{k}={v}" for k, v in input_hashes.items()))
    model_json = dict(schema=SCHEMA, features=list(FEATURES), coef=[coef], intercept=intercept,
                      block_probability=BLOCK_PROBABILITY, trained_on=trained_on, note=NOTE)
    raw = (json.dumps(model_json, indent=2) + "\n").encode()
    model = WindowModel(raw)  # runtime loader; all probabilities below use its math, not predict_proba

    threshold = (math.log(BLOCK_PROBABILITY / (1 - BLOCK_PROBABILITY)) - intercept) / coef
    first_n60 = next((n for n in range(1, 1001) if model.probability({"n60": n}) >= BLOCK_PROBABILITY), None)
    report = dict(model=dict(schema=SCHEMA, features=list(FEATURES), coef=coef, intercept=intercept,
                             block_probability=BLOCK_PROBABILITY, implied_n60_threshold=threshold,
                             smallest_integer_n60_flagged=first_n60, sha256=model.sha256,
                             hyperparameters=HYPERPARAMETERS, sklearn=sklearn.__version__, numpy=np.__version__),
                  training_rows={k: int(sum(1 for (_, label) in rows if label == v)) for k, v in LABELS.items()},
                  max_n60_by_kind={}, editions={}, input_sha256=input_hashes)
    for edition in EDITIONS:
        for a, f in data[edition]:
            report["max_n60_by_kind"][a["kind"]] = max(report["max_n60_by_kind"].get(a["kind"], 0), f["n60"])
        report["editions"][edition] = ev.evaluate(CORPUS / edition, model)
    report["summary"] = ev.summarise(report["editions"])
    humans_isolated = report["summary"]["human_clients_isolated"]
    report["stop"] = humans_isolated > 0

    for edition, result in report["editions"].items():
        print(ev.table(edition, result))
    print(json.dumps(dict(report["model"], training_rows=report["training_rows"],
                          max_n60_by_kind=report["max_n60_by_kind"], summary=report["summary"]), indent=2))
    (ev.HERE / "training-report.json").write_text(json.dumps(report, indent=2) + "\n")
    if humans_isolated:
        print(f"STOP: {humans_isolated} human client(s) isolated at p >= {BLOCK_PROBABILITY} on training data. "
              "Model and manifest NOT written.")
        return 1

    if ev.MODEL_PATH.exists() and ev.MODEL_PATH.read_bytes() != raw:
        print(f"ERROR: {ev.MODEL_PATH} is frozen and differs from this run; not overwriting.")
        return 2
    ev.MODEL_PATH.write_bytes(raw)
    assert WindowModel(ev.MODEL_PATH.read_bytes()).sha256 == model.sha256
    print(f"model written: {ev.MODEL_PATH} sha256={model.sha256}")

    if ev.MANIFEST_PATH.exists():
        frozen = json.loads(ev.MANIFEST_PATH.read_text())["model_sha256"]
        print(f"manifest already written; model sha256 {'matches' if frozen == model.sha256 else 'DIFFERS'}")
        return 0 if frozen == model.sha256 else 2
    manifest = dict(
        written_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        purpose="Pre-commitment for the client-window-v1 held-out evaluation; written before any held-out data.",
        model_file="models/client_window_v1.json", model_sha256=model.sha256, schema=SCHEMA, features=list(FEATURES),
        coef=coef, intercept=intercept, block_probability=BLOCK_PROBABILITY, implied_n60_threshold=threshold,
        smallest_integer_n60_flagged=first_n60, training_input_sha256=input_hashes,
        scripts_sha256={p.name: sha256(p) for p in (ev.HERE / "train_window_model.py", ev.HERE / "evaluate_window_model.py")},
        evaluation_command="python3 -I docs/evidence/2026-11-05-ai-window/model/evaluate_window_model.py <run-dir> [...]",
        acceptance_rule=ev.ACCEPTANCE_RULE)
    ev.MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"manifest written: {ev.MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
