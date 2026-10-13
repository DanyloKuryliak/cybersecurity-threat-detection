import pytest
from fastapi.testclient import TestClient

from threat_detection import service
from threat_detection.load_alerts import alert_rows


def test_only_aliased_hosts_enter_alert_store():
    alert = {"minute": "2011-08-19T10:00", "source": "10.0.0.1", "score": 0.8,
             "flow_count": 1, "icmp_flows": 0, "total_bytes": 100, "botnet": 1}
    with pytest.raises(ValueError, match="aliased hosts"):
        alert_rows({"alerts": [alert], "holdout_alerts": []})
    rows = alert_rows({"alerts": [alert | {"source": "host-01"}], "holdout_alerts": []})
    assert rows[0][0] == "52:2011-08-19T10:00:host-01"


def test_local_review_rejects_stale_update(monkeypatch, tmp_path):
    alert = {"alert_id": "53:2011-08-19T10:00:host-01", "capture": 53,
             "minute": "2011-08-19T10:00", "host": "host-01", "score": 0.8,
             "flow_count": 2, "icmp_flows": 0, "total_bytes": 100, "known_label": 1}
    monkeypatch.setattr(service, "REVIEW_DB", tmp_path / "reviews.sqlite3")
    monkeypatch.setattr(service, "query_alerts", lambda sql, parameters=None: [alert.copy()])
    client = TestClient(service.app)
    url = f"/v1/alerts/{alert['alert_id']}"
    assert client.get("/v1/alerts?capture=99").status_code == 400
    assert client.get("/v1/alerts?capture=53").json()["total"] == 1
    body = {"status": "needs_more_data", "note": "Inspect traffic", "version": 0}
    assert client.post(url + "/review", json=body).json()["version"] == 1
    assert client.post(url + "/review", json=body).status_code == 409
    assert client.get(url).json()["review"]["status"] == "needs_more_data"
    assert client.get("/v1/alerts?status=unreviewed").json()["total"] == 0
