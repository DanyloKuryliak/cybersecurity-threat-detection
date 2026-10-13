# Local research API

FastAPI runs through local Docker Compose at `http://127.0.0.1:8765`. It reads only aliased alert summaries from ClickHouse and keeps review notes in local SQLite. The API has no login and must not be exposed beyond localhost. Known botnet labels are included for research and are not analyst decisions.

| Endpoint | Current behavior |
| --- | --- |
| `GET /` | Analyst page |
| `GET /research` | Model result page |
| `GET /report.json` | Local research report |
| `GET /v1/health` | Database status and alert count |
| `GET /v1/alerts` | Search by capture, host alias, review status; cursor and limit |
| `GET /v1/alerts/{id}` | One alert's summary and current review |
| `POST /v1/alerts/{id}/review` | Save status and note with expected version; stale versions return `409` |

Review JSON: `{"status":"needs_more_data","note":"Check nearby flows","version":0}`. The version starts at 0 for an unreviewed alert and increments after each saved review. Capture is limited to 52 or 53, list size to 100, and host is an exact alias match. Returned time is the capture's local clock time, not asserted UTC.

This local API does not implement live ingestion, source event lookup, SSO, roles, or production audit identity. Before any deployment, those controls and real-data permissions must be designed and tested. A public site would use a separately reviewed export.

The score is an anomaly ranking, not a threat probability. `suspicious` is an analyst assessment, not a model-generated fact.
