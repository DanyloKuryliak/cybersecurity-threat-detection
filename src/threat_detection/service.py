"""Local analyst API over aliased CTU-13 research alerts."""

import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from threat_detection.ctu13 import OUTPUT, PROJECT
from threat_detection.load_alerts import client

app = FastAPI(title="CTU-13 Local Investigation", version="0.1.0")
REVIEW_DB = Path(os.getenv("CTU_REVIEW_DB", OUTPUT / "reviews.sqlite3"))


class Review(BaseModel):
    status: Literal["benign", "suspicious", "needs_more_data"]
    note: str = Field(max_length=500)
    version: int = Field(ge=0)


def review_connection():
    REVIEW_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(REVIEW_DB)
    connection.execute("""CREATE TABLE IF NOT EXISTS reviews (
        alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, note TEXT NOT NULL,
        version INTEGER NOT NULL, updated_at TEXT NOT NULL)""")
    connection.execute("""CREATE TABLE IF NOT EXISTS review_events (
        alert_id TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL,
        version INTEGER NOT NULL, updated_at TEXT NOT NULL)""")
    return connection


def reviews_for(ids: list[str]) -> dict[str, dict]:
    if not ids:
        return {}
    with closing(review_connection()) as connection:
        placeholders = ",".join("?" for _ in ids)
        rows = connection.execute(
            f"SELECT alert_id,status,note,version,updated_at FROM reviews WHERE alert_id IN ({placeholders})", ids
        ).fetchall()
    return {row[0]: dict(zip(("status", "note", "version", "updated_at"), row[1:], strict=True))
            for row in rows}


def query_alerts(sql: str, parameters: dict | None = None) -> list[dict]:
    db = client()
    try:
        return list(db.query(sql, parameters=parameters or {}).named_results())
    finally:
        db.close()


@app.get("/")
def home():
    return FileResponse(PROJECT / "web" / "analyst.html")


@app.get("/research")
def research():
    return FileResponse(PROJECT / "web" / "ctu13.html")


@app.get("/report.json")
def report():
    return FileResponse(OUTPUT / "report.json")


@app.get("/v1/health")
def health():
    try:
        count = query_alerts("SELECT count() AS alerts FROM alerts")[0]["alerts"]
    except Exception as error:
        raise HTTPException(status_code=503, detail="Alert store unavailable") from error
    return {"status": "local_research", "alerts": count}


@app.get("/v1/alerts")
def list_alerts(
    capture: int | None = None,
    host: str | None = Query(default=None, max_length=32),
    status: Literal["unreviewed", "benign", "suspicious", "needs_more_data"] | None = None,
    cursor: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=100),
):
    where, parameters = [], {}
    if capture is not None:
        if capture not in (52, 53):
            raise HTTPException(status_code=400, detail="Capture must be 52 or 53")
        where.append("capture = {capture:UInt16}")
        parameters["capture"] = capture
    if host:
        where.append("host = {host:String}")
        parameters["host"] = host
    clause = " WHERE " + " AND ".join(where) if where else ""
    rows = query_alerts("SELECT alert_id,capture,minute,host,score,flow_count,icmp_flows,"
                        "total_bytes,known_label FROM alerts" + clause +
                        " ORDER BY score DESC, alert_id", parameters)
    saved = reviews_for([row["alert_id"] for row in rows])
    for row in rows:
        row["review"] = saved.get(row["alert_id"], {"status": "unreviewed", "note": "", "version": 0})
    if status:
        rows = [row for row in rows if row["review"]["status"] == status]
    page = rows[cursor:cursor + limit]
    return {"total": len(rows), "items": page,
            "next_cursor": cursor + limit if cursor + limit < len(rows) else None}


@app.get("/v1/alerts/{alert_id}")
def get_alert(alert_id: str):
    rows = query_alerts("SELECT alert_id,capture,minute,host,score,flow_count,icmp_flows,"
                        "total_bytes,known_label FROM alerts WHERE alert_id = {id:String}",
                        {"id": alert_id})
    if not rows:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = rows[0]
    alert["review"] = reviews_for([alert_id]).get(alert_id, {"status": "unreviewed", "note": "", "version": 0})
    return alert


@app.post("/v1/alerts/{alert_id}/review")
def review_alert(alert_id: str, review: Review):
    get_alert(alert_id)
    with closing(review_connection()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute("SELECT version FROM reviews WHERE alert_id = ?", (alert_id,)).fetchone()
        version = current[0] if current else 0
        if review.version != version:
            raise HTTPException(status_code=409, detail="Review changed; reload the alert")
        updated = datetime.now(UTC).isoformat(timespec="seconds")
        connection.execute("""INSERT INTO reviews VALUES (?,?,?,?,?)
            ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status,note=excluded.note,
            version=excluded.version,updated_at=excluded.updated_at""",
            (alert_id, review.status, review.note, version + 1, updated))
        connection.execute("INSERT INTO review_events VALUES (?,?,?,?,?)",
                           (alert_id, review.status, review.note, version + 1, updated))
    return {"status": review.status, "note": review.note, "version": version + 1, "updated_at": updated}
