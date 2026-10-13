"""Load aliased CTU-13 research alerts into local ClickHouse."""

import json
import os
from pathlib import Path

import clickhouse_connect

from threat_detection.ctu13 import OUTPUT


def client():
    password = os.environ["CTU_DB_PASSWORD"]
    return clickhouse_connect.get_client(
        host=os.getenv("CTU_DB_HOST", "localhost"),
        port=int(os.getenv("CTU_DB_PORT", "8123")),
        username=os.getenv("CTU_DB_USER", "ctu"),
        password=password,
        database=os.getenv("CTU_DB_NAME", "threat_detection"),
    )


def alert_rows(report: dict) -> list[list]:
    rows = []
    for capture, name in ((52, "alerts"), (53, "holdout_alerts")):
        for alert in report[name]:
            host = alert["source"]
            if not host.startswith("host-"):
                raise ValueError("Only aliased hosts may enter the local alert store")
            rows.append([
                f"{capture}:{alert['minute']}:{host}", capture, alert["minute"], host,
                float(alert["score"]), int(alert["flow_count"]), int(alert["icmp_flows"]),
                int(alert["total_bytes"]), int(alert["botnet"]),
            ])
    return rows


def load() -> None:
    path = Path(os.getenv("CTU_REPORT_PATH", OUTPUT / "report.json"))
    report = json.loads(path.read_text())
    rows = alert_rows(report)
    db = client()
    try:
        db.command("""CREATE TABLE IF NOT EXISTS alerts (
            alert_id String, capture UInt16, minute String, host String, score Float64,
            flow_count UInt32, icmp_flows UInt32, total_bytes UInt64, known_label UInt8,
            loaded_at DateTime DEFAULT now()
        ) ENGINE = MergeTree
          PARTITION BY capture ORDER BY alert_id
          TTL loaded_at + INTERVAL 30 DAY""")
        db.command("TRUNCATE TABLE alerts")
        if rows:
            db.insert("alerts", rows, column_names=["alert_id", "capture", "minute", "host",
                      "score", "flow_count", "icmp_flows", "total_bytes", "known_label"])
        actual = int(db.query("SELECT count() FROM alerts").first_item["count()"])
        if actual != len(rows):
            raise RuntimeError(f"Alert reconciliation failed: {actual} stored, {len(rows)} expected")
        print(f"Loaded {actual} aliased alerts into local ClickHouse")
    finally:
        db.close()


if __name__ == "__main__":
    load()
