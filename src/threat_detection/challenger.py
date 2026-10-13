"""Train a small PyTorch novelty-model challenger on CTU-13 normal flows."""

import hashlib
import json
from pathlib import Path

import dask.dataframe as dd
import numpy as np
import torch
from torch import nn

from threat_detection.ctu13 import (
    CAPTURES,
    FEATURES,
    OUTPUT,
    fixed_budget,
    group_windows,
    summarize,
    summarize_alerts,
)


def load_features(role: str):
    path = OUTPUT / "features" / role
    if not path.exists():
        raise FileNotFoundError("Run threat-ctu13-backfill before training the challenger")
    return dd.read_parquet(path).compute()


def train() -> None:
    manifest = json.loads((OUTPUT / "features" / "manifest.json").read_text())
    if manifest["schema_version"] != "ctu13-flow-v1" or tuple(manifest["features"]) != FEATURES:
        raise ValueError("Parquet feature schema does not match the current model schema")
    train_frame = load_features("train")
    normal = train_frame.loc[train_frame.target == 0, list(FEATURES)].to_numpy(dtype=np.float32)
    if len(normal) < 100:
        raise ValueError("Too few normal training flows")
    mean = normal.mean(axis=0)
    scale = normal.std(axis=0)
    scale[scale == 0] = 1
    torch.manual_seed(42)
    torch.set_num_threads(2)
    model = nn.Sequential(nn.Linear(12, 8), nn.ReLU(), nn.Linear(8, 4), nn.ReLU(),
                          nn.Linear(4, 8), nn.ReLU(), nn.Linear(8, 12))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    inputs = torch.from_numpy((normal - mean) / scale)
    model.train()
    for _ in range(100):
        optimizer.zero_grad()
        loss = nn.functional.mse_loss(model(inputs), inputs)
        loss.backward()
        optimizer.step()
    model.eval()

    def windows(role: str) -> list[dict]:
        frame = load_features(role)
        data = torch.from_numpy((frame[list(FEATURES)].to_numpy(dtype=np.float32) - mean) / scale)
        with torch.no_grad():
            scores = nn.functional.mse_loss(model(data), data, reduction="none").mean(dim=1).numpy()
        records = frame[["minute", "source", "protocol", "bytes", "target"]].to_dict("records")
        return group_windows(records, scores)

    validation = windows("validation")
    threshold = float(np.quantile([row["score"] for row in validation], 0.95))
    outcomes = {role: windows(role) for role in ("test", "holdout")}
    report = {
        "model": "12-8-4-8-12 PyTorch autoencoder; mean reconstruction error",
        "features": FEATURES,
        "feature_schema_version": manifest["schema_version"],
        "source_sha256": manifest["source_sha256"],
        "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "train_capture": CAPTURES["train"][0],
        "train_normal_flows": len(normal),
        "epochs": 100,
        "seed": 42,
        "final_train_loss": round(loss.item(), 6),
        "validation_cutoff": round(threshold, 6),
        "threshold_policy": "95th percentile of unlabeled validation host-minute scores",
        "validation": summarize(validation, threshold),
        "test": summarize(outcomes["test"], threshold),
        "holdout": summarize(outcomes["holdout"], threshold),
        "fixed_budget": {role: summarize_alerts(rows, fixed_budget(rows))
                         for role, rows in outcomes.items()},
        "status": "research challenger only; no deployment or automatic model promotion",
    }
    target = OUTPUT / "challenger"
    target.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), target / "weights.pt")
    (target / "preprocessing.json").write_text(json.dumps({"schema_version": manifest["schema_version"],
        "features": FEATURES, "mean": mean.tolist(), "scale": scale.tolist(), "seed": 42,
        "epochs": 100, "train_capture": CAPTURES["train"][0],
        "train_source_sha256": manifest["source_sha256"]["train"]}, indent=2) + "\n")
    (target / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("validation", "test", "holdout", "status")}, indent=2))


if __name__ == "__main__":
    train()
