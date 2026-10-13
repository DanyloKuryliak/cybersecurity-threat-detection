"""Reproducible cross-capture CTU-13 botnet-detection pilot."""

import csv
import hashlib
import json
import math
import os
import shutil
import ssl
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import median
from urllib.request import urlopen

import certifi
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score

PROJECT = Path(os.getenv("CTU_PROJECT_ROOT", Path(__file__).parents[2]))
DATA = PROJECT / "data" / "ctu13"
OUTPUT = PROJECT / "artifacts" / "ctu13"
BASE_URL = "https://mcfp.felk.cvut.cz/publicDatasets"
CAPTURES = {
    "train": (46, "capture20110815-2.binetflow", "ef5c9ed6895d4ca5aec723449dae30054ccd1f6b091713a52ffcb681ff78a02c"),
    "validation": (48, "capture20110816-2.binetflow", "df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680"),
    "test": (52, "capture20110818-2.binetflow", "cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c"),
    "holdout": (53, "capture20110819.binetflow", "1098f0addacedc321c7baefad63ef0d9a0f26630d0155087d37e8da770dd9f2e"),
}
REQUIRED = {"StartTime", "Dur", "Proto", "SrcAddr", "Dport", "TotPkts", "TotBytes", "SrcBytes", "Label"}
FEATURES = (
    "log_duration", "log_packets", "log_bytes", "log_source_bytes",
    "tcp", "udp", "icmp", "port_53", "port_80", "port_443", "other_system_port", "high_port",
)


def file_path(capture: tuple[int, str, str]) -> Path:
    scenario, filename, _ = capture
    return DATA / f"{scenario}-{filename}"


def verify_file(path: Path, expected_sha256: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {path.name}; run threat-ctu13-download")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected_sha256:
        raise ValueError(f"Checksum mismatch for {path.name}; remove it and download again")


def download() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    for scenario, filename, expected_sha256 in CAPTURES.values():
        capture = (scenario, filename, expected_sha256)
        target = file_path(capture)
        if not target.exists():
            url = f"{BASE_URL}/CTU-Malware-Capture-Botnet-{scenario}/detailed-bidirectional-flow-labels/{filename}"
            temporary = target.with_name(target.name + ".part")
            try:
                context = ssl.create_default_context(cafile=certifi.where())
                with urlopen(url, timeout=60, context=context) as response, temporary.open("wb") as handle:
                    shutil.copyfileobj(response, handle)
                verify_file(temporary, expected_sha256)
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
        verify_file(target, expected_sha256)
        print(f"Verified {target.name}")


def flow_features(row: dict[str, str]) -> list[float]:
    numeric = [float(row[name]) for name in ("Dur", "TotPkts", "TotBytes", "SrcBytes")]
    if any(not math.isfinite(value) or value < 0 for value in numeric):
        raise ValueError("Flow measurements must be finite and nonnegative")
    port = int(row["Dport"]) if row["Dport"].isdigit() else -1
    protocol = row["Proto"]
    return [math.log1p(value) for value in numeric] + [
        float(protocol == name) for name in ("tcp", "udp", "icmp")
    ] + [float(port == number) for number in (53, 80, 443)] + [
        float(0 < port < 1024), float(port >= 1024)
    ]


def load_capture(path: Path) -> tuple[np.ndarray, np.ndarray, list[dict], dict]:
    vectors, labels, records = [], [], []
    total = 0
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not REQUIRED.issubset(reader.fieldnames or []):
            raise ValueError(f"Unexpected CTU-13 columns in {path.name}")
        for row in reader:
            total += 1
            label = row["Label"]
            if label.startswith("flow=From-Normal"):
                target = 0
            elif label.startswith("flow=From-Botnet"):
                target = 1
            else:
                continue  # Background and To-Botnet have no trustworthy binary target.
            minute = datetime.strptime(row["StartTime"][:16], "%Y/%m/%d %H:%M")
            vectors.append(flow_features(row))
            labels.append(target)
            records.append({
                "minute": minute.isoformat(timespec="minutes"),
                "source": row["SrcAddr"],
                "protocol": row["Proto"],
                "bytes": int(float(row["TotBytes"])),
                "target": target,
            })
    if not vectors:
        raise ValueError(f"No known-origin flows in {path.name}")
    counts = {"all_flows": total, "known_origin_flows": len(labels), "botnet_flows": sum(labels), "excluded_unknown_flows": total - len(labels)}
    return np.asarray(vectors, dtype=np.float32), np.asarray(labels, dtype=np.int8), records, counts


def group_windows(records: list[dict], scores: np.ndarray) -> list[dict]:
    if len(records) != len(scores):
        raise ValueError("A score is required for every known-origin flow")
    groups = defaultdict(list)
    for record, score in zip(records, scores, strict=True):
        groups[(record["minute"], record["source"])].append((record, float(score)))
    windows = []
    for (minute, source), flows in sorted(groups.items()):
        windows.append({
            "minute": minute,
            "source": source,
            "flow_count": len(flows),
            "score": float(np.mean([score for _, score in flows])),
            "total_bytes": sum(record["bytes"] for record, _ in flows),
            "icmp_flows": sum(record["protocol"] == "icmp" for record, _ in flows),
            "botnet": int(any(record["target"] for record, _ in flows)),
        })
    return windows


def summarize_alerts(windows: list[dict], flagged: list[dict]) -> dict:
    positives = sum(window["botnet"] for window in windows)
    hits = sum(window["botnet"] for window in flagged)
    minutes = [datetime.fromisoformat(window["minute"]) for window in windows]
    elapsed_hours = ((max(minutes) - min(minutes)).total_seconds() / 60 + 1) / 60
    first_botnet = {}
    first_detected = {}
    for window in windows:
        if window["botnet"]:
            first_botnet.setdefault(window["source"], datetime.fromisoformat(window["minute"]))
    for window in flagged:
        if window["botnet"]:
            moment = datetime.fromisoformat(window["minute"])
            source = window["source"]
            first_detected[source] = min(first_detected.get(source, moment), moment)
    delays = [(moment - first_botnet[source]).total_seconds() / 60
              for source, moment in first_detected.items()]
    return {
        "windows": len(windows),
        "botnet_windows": positives,
        "alerts": len(flagged),
        "botnet_windows_alerted": hits,
        "precision_on_known_labels": round(hits / len(flagged), 3) if flagged else 0,
        "recall_on_known_labels": round(hits / positives, 3) if positives else 0,
        "average_precision": round(float(average_precision_score(
            [window["botnet"] for window in windows],
            [window["score"] for window in windows],
        )), 3) if positives else None,
        "positive_rate": round(positives / len(windows), 3),
        "alerts_per_capture_hour": round(len(flagged) / elapsed_hours, 2),
        "botnet_sources_detected": len(delays),
        "botnet_sources_total": len(first_botnet),
        "median_detection_delay_minutes": round(median(delays), 1) if delays else None,
    }


def summarize(windows: list[dict], threshold: float) -> dict:
    return summarize_alerts(windows, [window for window in windows if window["score"] >= threshold])


def fixed_budget(windows: list[dict], fraction: float = 0.05) -> list[dict]:
    if not 0 < fraction <= 1:
        raise ValueError("Review fraction must be between zero and one")
    count = math.ceil(len(windows) * fraction)
    return sorted(windows, key=lambda row: (-row["score"], row["minute"], row["source"]))[:count]


def icmp_rule(windows: list[dict]) -> dict:
    flagged = [window for window in windows if window["icmp_flows"] > 0]
    return {
        "alerts": len(flagged),
        "botnet_windows_alerted": sum(window["botnet"] for window in flagged),
    }


def evaluate() -> None:
    loaded = {}
    for role, capture in CAPTURES.items():
        path = file_path(capture)
        verify_file(path, capture[2])
        loaded[role] = load_capture(path)
    train_x, train_y, _, train_counts = loaded["train"]
    if sum(train_y == 0) < 100:
        raise ValueError("Too few known-normal training flows")
    model = IsolationForest(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(train_x[train_y == 0])

    val_x, _, val_records, val_counts = loaded["validation"]
    test_x, _, test_records, test_counts = loaded["test"]
    holdout_x, _, holdout_records, holdout_counts = loaded["holdout"]
    validation = group_windows(val_records, -model.score_samples(val_x))
    test = group_windows(test_records, -model.score_samples(test_x))
    holdout = group_windows(holdout_records, -model.score_samples(holdout_x))
    threshold = float(np.quantile([window["score"] for window in validation], 0.95))
    def report_alerts(windows: list[dict]) -> list[dict]:
        aliases = {source: f"host-{index:02d}" for index, source in enumerate(
            sorted({row["source"] for row in windows}), 1)}
        return [row | {"source": aliases[row["source"]], "score": round(row["score"], 4)}
                for row in sorted((row for row in windows if row["score"] >= threshold),
                                  key=lambda row: row["score"], reverse=True)]

    report = {
        "source": "CTU-13 labeled bidirectional flow captures 46, 48, 52, and 53",
        "source_url": "https://www.stratosphereips.org/datasets-ctu13",
        "license": "Creative Commons Attribution; cite Garcia et al., Computers & Security 45 (2014), 100–123",
        "unit": "known-origin source host per capture-local minute",
        "model": "Isolation Forest trained on scenario 46 From-Normal flows",
        "features": FEATURES,
        "threshold": round(threshold, 4),
        "threshold_policy": "top 5% of validation host-minute anomaly scores, ignoring validation labels",
        "capture_counts": {"train": train_counts, "validation": val_counts,
                           "test": test_counts, "holdout": holdout_counts},
        "validation": summarize(validation, threshold),
        "test": summarize(test, threshold),
        "holdout": summarize(holdout, threshold),
        "fixed_budget": {role: summarize_alerts(windows, fixed_budget(windows))
                         for role, windows in (("test", test), ("holdout", holdout))},
        "icmp_rule": {role: icmp_rule(windows) for role, windows in
                      (("validation", validation), ("test", test), ("holdout", holdout))},
        "alerts": report_alerts(test),
        "holdout_alerts": report_alerts(holdout),
        "limitations": "Only known-origin flows are scored; Background and To-Botnet are excluded. Four short 2011 captures cannot establish real-world performance. Scores are not threat probabilities. Fixed-budget rankings require an entire capture before selecting alerts.",
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(PROJECT / "web" / "ctu13.html", OUTPUT / "index.html")
    print(json.dumps({key: report[key] for key in ("source", "threshold", "validation", "test", "holdout", "limitations")}, indent=2))


if __name__ == "__main__":
    evaluate()
