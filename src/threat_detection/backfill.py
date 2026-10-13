"""Optional Dask/Parquet feature backfill for the public CTU-13 captures."""

import json
from pathlib import Path

import dask.dataframe as dd
import numpy as np

from threat_detection.ctu13 import CAPTURES, FEATURES, OUTPUT, file_path, verify_file


def feature_frame(path: Path) -> dd.DataFrame:
    columns = ["StartTime", "Dur", "Proto", "SrcAddr", "Dport", "TotPkts", "TotBytes", "SrcBytes", "Label"]
    frame = dd.read_csv(path, usecols=columns, dtype="string", blocksize="16MB")
    normal = frame.Label.str.startswith("flow=From-Normal")
    botnet = frame.Label.str.startswith("flow=From-Botnet")
    frame = frame[normal | botnet]
    port = dd.to_numeric(frame.Dport, errors="coerce").fillna(-1)
    measurements = {name: dd.to_numeric(frame[column], errors="raise")
                    for name, column in zip(FEATURES[:4], ("Dur", "TotPkts", "TotBytes", "SrcBytes"), strict=True)}
    output = frame[["StartTime", "SrcAddr"]].rename(columns={"StartTime": "minute", "SrcAddr": "source"})
    output["minute"] = dd.to_datetime(output.minute.str.slice(0, 16), format="%Y/%m/%d %H:%M").dt.strftime("%Y-%m-%dT%H:%M")
    output["protocol"] = frame.Proto
    output["bytes"] = measurements["log_bytes"].astype("int64")
    output["target"] = botnet[normal | botnet].astype("int8")
    for name, values in measurements.items():
        output[name] = np.log1p(values)
    for name in ("tcp", "udp", "icmp"):
        output[name] = (frame.Proto == name).astype("int8")
    for name, number in (("port_53", 53), ("port_80", 80), ("port_443", 443)):
        output[name] = (port == number).astype("int8")
    output["other_system_port"] = ((port > 0) & (port < 1024)).astype("int8")
    output["high_port"] = (port >= 1024).astype("int8")
    return output


def backfill() -> None:
    root = OUTPUT / "features"
    root.mkdir(parents=True, exist_ok=True)
    counts = {}
    for role, capture in CAPTURES.items():
        path = file_path(capture)
        verify_file(path, capture[2])
        target = root / role
        frame = feature_frame(path)
        frame.to_parquet(target, write_index=False, overwrite=True)
        stored = dd.read_parquet(target)
        counts[role] = {"rows": int(stored.shape[0].compute()),
                        "botnet_rows": int(stored.target.sum().compute()),
                        "partitions": stored.npartitions}
    (root / "manifest.json").write_text(json.dumps({"schema_version": "ctu13-flow-v1",
        "features": FEATURES, "source_sha256": {role: capture[2] for role, capture in CAPTURES.items()},
        "captures": counts}, indent=2) + "\n")
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    backfill()
