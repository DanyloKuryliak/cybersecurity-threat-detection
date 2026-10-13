# Cybersecurity Threat Detection

A local network-flow detection study using real CTU-13 university network captures. It is research for analyst review, not a deployed security control.

## Real-data study: CTU-13

The [Stratosphere Laboratory CTU-13 dataset](https://www.stratosphereips.org/datasets-ctu13) contains real network traffic mixed with controlled botnet activity. This project uses four labeled **bidirectional flow** files: capture 46 for known-normal training, 48 for threshold selection, and 52 and 53 for later checks. It downloads no malware executables or packet payloads. Raw files and local outputs stay outside Git.

From this project directory:

```bash
uv sync --group dev --extra service
uv run threat-ctu13-download
uv run threat-ctu13-evaluate
python3 -m http.server 8765 --bind 127.0.0.1 --directory artifacts/ctu13
```

Open `http://localhost:8765` to inspect the local report. The model sees flow measurements, never labels or IP addresses. It scores one-minute source-host windows; labels are joined afterward for evaluation. Only clearly labeled `From-Normal` and `From-Botnet` flows are used; `Background` and `To-Botnet` do not mean "normal" or "malicious." See [the source and label decision](docs/DATA.md).

The original cutoff found **0/5** labeled botnet host-minutes in validation capture 48, **5/11** in capture 52 with 8 alerts, and **85/105** in capture 53 with 97 alerts. Review load rose sharply. A fixed top-5% batch budget reduced capture 53 to 13 alerts but found only 13/105 botnet minutes. The PyTorch challenger ranked lower than Isolation Forest at that small review budget. These results do not establish operational readiness.

[Read the full comparison](docs/RESULTS.md).

## Local investigation stack

After generating the report, create a local database password once, then start the containers:

```bash
python3 -c 'from pathlib import Path; import secrets; p=Path(".env"); p.write_text("CTU_DB_PASSWORD="+secrets.token_urlsafe(30)+"\n") if not p.exists() else None'
docker compose up --build -d
```

Open `http://localhost:8765` for the alert queue or `/research` for the model result. ClickHouse holds aliased alert summaries; FastAPI provides search, details, and local review notes. SQLite stores review history. The loader replaces derived alert rows when the report changes. Stop with `docker compose down` (local volumes remain).

The API has **no login** and binds to localhost. It is a local research workflow, not a hosted service.

## Optional larger-data and model experiments

```bash
docker compose --profile research run --build --rm research
docker compose --profile research run --rm research threat-ctu13-challenger
```

Dask reads the four CSVs and writes partitioned Parquet features. PyTorch fits a small autoencoder on capture 46 normal flows and scores later captures. Outputs and model weights stay under ignored `artifacts/`. The normal baseline runs without these extra tools; the four files fit on one machine.

To run the checks:

```bash
uv run --group dev --extra service pytest
uv run --group dev --extra service ruff check .
uv run threat-ctu13-evaluate  # after downloading the CTU-13 files
docker compose config --quiet  # after creating .env
```

## Project map

| Path | Purpose |
| --- | --- |
| `src/threat_detection/ctu13.py` | Verified CTU-13 download, cross-capture evaluation, and report |
| `src/threat_detection/backfill.py` | Optional Dask CSV-to-Parquet backfill |
| `src/threat_detection/challenger.py` | PyTorch model comparison |
| `src/threat_detection/load_alerts.py`, `service.py` | Local ClickHouse loader and analyst API |
| `web/ctu13.html` | Local research-result view |
| `web/analyst.html` | Local alert search, detail, and review page |
| `compose.yaml`, `Dockerfile` | Local database, API, and research containers |
| `tests/` | Contract and leakage checks |
| `docs/PLAN.md` | Acceptance criteria and staged delivery |
| `docs/ARCHITECTURE.md` | Local flow and proposed production design |
| `docs/DATA.md` | Source decision, schema, and privacy boundary |
| `docs/API.md` | Proposed production API contract |
| `docs/RESULTS.md` | Verified CTU-13 metrics, simple-rule comparison, and limits |
| `.github/workflows/verify.yml` | Checks for a standalone GitHub repository |

## Status and boundaries

The CTU-13 files are historical public research data, not access to a current organization or evidence of production performance. Dask, PyTorch, ClickHouse, and the local API are implemented as optional local workflows. Live sensors, durable streaming, organization login, security operations, and hosting still need an owner and authorized data. No live traffic, packet contents, credentials, or model weights are committed. The local report includes benchmark labels; a future public site would need a separate reviewed export.

The local research project is complete and reproducible with the commands above. [The delivery plan](docs/PLAN.md) separates completed local work from the conditional work required before any real deployment.
