"""Real-mode scenario building, with stand-in models and a tiny CSV.

The trained models and UNSW CSVs are not in the repo, so this checks the code
path (column handling, scoring, JSON-safe output) without them. On a machine
with the real artifacts, `python -m src.agent.scenario --mode real` runs the same code.
"""

import json

import numpy as np
import pandas as pd

from src.agent import scenario


class FakeModel:
    def __init__(self, classes, seen):
        self.classes = np.array(classes)
        self.named_steps = {"clf": self}
        self.seen = seen

    @property
    def classes_(self):
        return self.classes

    def predict_proba(self, X):
        self.seen.append(list(X.columns))
        p = np.full((len(X), len(self.classes)), 1 / len(self.classes))
        return p


def test_real_rows_scores_sampled_flows(tmp_path, monkeypatch):
    rows = []
    for i, cls in enumerate(["Normal", "Exploits", "Backdoors", "Worms", "DoS"] * 4):
        rows.append({"id": i, "proto": "tcp", "service": "http", "state": "FIN",
                     "dur": 0.5, "spkts": np.int64(4), "dpkts": 2, "sbytes": 300,
                     "rate": 12.5, "label": int(cls != "Normal"), "attack_cat": cls})
    csv = tmp_path / "test.csv"
    pd.DataFrame(rows).to_csv(csv, index=False)

    import joblib

    import src.detect.classifier as clf
    seen: list = []
    models = {"stage1_binary.joblib": FakeModel(["0", "1"], seen),
              "stage2_multiclass.joblib": FakeModel(["exploitation", "persistence", "normal"], seen)}
    monkeypatch.setattr(clf, "TEST_CSV", str(csv))
    monkeypatch.setattr(joblib, "load", lambda p: models[p.name])

    sample, source, classes = scenario._real_rows(seed=1)
    out = sample(["backdoor", "worms"], 5)

    assert source == str(csv) and classes == ["exploitation", "persistence", "normal"]
    assert len(out) == 5
    for p_atk, dist, ev in out:
        assert 0 <= p_atk <= 1 and set(dist) == set(classes)
        json.dumps({"p": p_atk, "d": dist, "e": ev})          # must be JSON-safe
        assert ev["proto"] == "tcp" and ev["src_pkts"] == 4
    for cols in seen:                                          # labels never reach the model
        assert not {"id", "label", "attack_cat", "_cls"} & set(cols)
