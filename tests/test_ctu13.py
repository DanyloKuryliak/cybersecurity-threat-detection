import csv

import numpy as np
import pytest

from threat_detection.ctu13 import (
    CAPTURES,
    REQUIRED,
    fixed_budget,
    flow_features,
    group_windows,
    icmp_rule,
    load_capture,
    summarize,
)


def sample(label, minute="2011/08/15 16:43", source="10.0.0.1"):
    return {
        "StartTime": minute + ":20.000000", "Dur": "1", "Proto": "tcp", "SrcAddr": source,
        "Dport": "443", "TotPkts": "2", "TotBytes": "100", "SrcBytes": "50", "Label": label,
    }


def test_only_source_labels_are_evaluation_truth(tmp_path):
    path = tmp_path / "capture.binetflow"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=sorted(REQUIRED))
        writer.writeheader()
        writer.writerows([
            sample("flow=From-Normal-V46-A"),
            sample("flow=To-Botnet-V46-A"),
            sample("flow=Background"),
            sample("flow=From-Botnet-V46-A", source="10.0.0.2") | {"Proto": "icmp", "Dport": ""},
        ])
    features, labels, records, counts = load_capture(path)
    assert features.shape == (2, 12)
    assert labels.tolist() == [0, 1]
    assert counts == {"all_flows": 4, "known_origin_flows": 2, "botnet_flows": 1, "excluded_unknown_flows": 2}
    windows = group_windows(records, np.array([0.2, 0.8]))
    assert summarize(windows, 0.5)["botnet_windows_alerted"] == 1
    assert icmp_rule(windows) == {"alerts": 1, "botnet_windows_alerted": 1}


def test_invalid_measurements_and_capture_split():
    with pytest.raises(ValueError, match="finite and nonnegative"):
        flow_features(sample("flow=From-Normal", source="10.0.0.1") | {"Dur": "nan"})
    assert flow_features(sample("flow=From-Normal", source="10.0.0.1")) == flow_features(
        sample("flow=From-Botnet", source="10.0.0.2")
    )
    assert [capture[0] for capture in CAPTURES.values()] == [46, 48, 52, 53]


def test_fixed_budget_and_detection_delay():
    windows = [
        {"minute": "2011-08-19T10:00", "source": "a", "score": 0.2, "botnet": 1},
        {"minute": "2011-08-19T10:01", "source": "a", "score": 0.9, "botnet": 1},
        {"minute": "2011-08-19T10:02", "source": "b", "score": 0.1, "botnet": 0},
    ]
    selected = fixed_budget(windows, 1 / 3)
    assert selected == [windows[1]]
    summary = summarize(windows, 0.8)
    assert summary["botnet_sources_detected"] == 1
    assert summary["median_detection_delay_minutes"] == 1
    with pytest.raises(ValueError, match="Review fraction"):
        fixed_budget(windows, 0)
