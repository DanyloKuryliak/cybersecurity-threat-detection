# Architecture

## Implemented CTU-13 research path

```text
four official labeled bidirectional-flow files
  → SHA-256 and schema checks → select known-origin flows
  → fit flow novelty detector on capture 46 known-normal records
  → score captures 48, 52, and 53 → average scores by source host and minute
  → choose threshold on capture 48 scores → evaluate on captures 52 and 53
  → local report and alert investigation page
```

Only known-origin flows are scored; `Background` and `To-Botnet` are excluded because their status is uncertain. IP addresses and labels do not enter model features. The local report aliases hosts, then shows labels only as benchmark truth. CTU-13 uses one-minute windows because the chosen captures are short. A fixed top-5% batch budget is compared with the validation cutoff; it requires the entire capture before choosing alerts and cannot serve as a live alert threshold.

## Implemented optional local stack

```text
verified CTU-13 CSVs → Dask feature conversion → partitioned local Parquet
                                                → PyTorch challenger report + ignored weights

Isolation Forest report → aliased alerts → ClickHouse → FastAPI → local analyst page
                                                    ↘ SQLite review state and audit rows
```

Docker Compose runs ClickHouse, a one-shot idempotent loader, and the local API. A separate research profile runs Dask and PyTorch inside a container. The loader replaces derived alerts from the current report and reconciles row counts. ClickHouse stores aliased alert summaries for 30 days after loading; SQLite stores local review notes and their update history. The API binds to localhost and has no authentication. This is an offline historical workflow, not live monitoring. The PyTorch challenger is never automatically promoted.

## Proposed production path

```text
authorized flow-log sensors
  → authenticated ingest + versioned schema validation + redaction
  → durable queue (event ID and source offsets)
       ├→ encrypted, access-controlled raw archive for replay
       └→ window worker → versioned features → rules + approved model scorer
                                      → alert sink → ClickHouse investigation tables
                                                     → authenticated analyst API/UI
                                                     → review outcomes and case audit

raw archive → Dask/Parquet backfills + time-split evaluation → model registry
                                                → shadow deployment → promoted scorer
```

**Data ownership and trust.** Sensors and source permissions are agreed before ingestion. The ingest edge authenticates senders, limits payload size/rate, validates timestamps and schema versions, removes fields outside the approved contract, and routes invalid rows to a restricted quarantine with counts and reasons. Raw flow records stay in a short-lived encrypted archive for replay; aggregate alert views have a separately approved retention period. Any public site receives only a reviewed, safe export.

**Processing and replay.** The queue buffers outages. A worker deduplicates by `event_id`, handles late events with an explicit lateness window, and builds five-minute windows keyed by source and UTC start. Its checkpoint or sink write is committed before acknowledging source offsets. Replays use the same feature code and produce the same `(source, window, feature_version)` key, so retries upsert rather than multiply alerts. A reconciliation job compares accepted, quarantined, archived, windowed, and scored counts. Late-arrival policy and exact queue/storage choices need measurement with the chosen sensors.

**Models.** The current study uses Isolation Forest as a research baseline and records an ICMP rule and PyTorch autoencoder as comparisons. The optional Dask backfill demonstrates a partitioned Parquet path, although the current files fit in memory. The challenger saves a schema version, preprocessing values, source hashes, code hash, weights, and evaluation locally. It ranked worse at the fixed 5% review budget on capture 52, so it is not promoted. A future service would need analyst-reviewed examples, stable alert budgets, shadow scoring, approval, and rollback. Scores rank review; they do not trigger automatic blocking.

**Investigation.** The local ClickHouse table holds aliased alert summaries only. The future version would also store normalized event references and windows for time-range queries. The local API validates filters and caps pagination; SQLite review updates use a version number to reject stale writes. A production service needs authenticated analysts, source event drill-down, case ownership, and an incident process. NIST's current incident-response guidance supports human validation, prioritization, and tracking rather than treating every detector output as a confirmed incident.

**Failure and security behavior.** Monitor source lag, queue depth, rejection rate, feature completeness, score distribution, alert volume, query latency, and analyst dispositions. If model scoring fails, preserve ingestion and expose a degraded state; approved deterministic rules may continue. If ClickHouse is unavailable, keep the durable queue/archive and replay after recovery. Use SSO/RBAC, encryption in transit and at rest, secret management, audit logs, backups, network isolation, and retention deletion. Test restore, failover, and replay before production. No model weight or raw telemetry belongs in a public repository.

## Why these components

- [Dask's own guidance](https://docs.dask.org/en/latest/dataframe-best-practices.html) recommends ordinary local dataframe tools while data fits in memory and Parquet for larger tabular datasets. That is why Dask is deferred until a measured scale need.
- [scikit-learn documents](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html) that lower `decision_function` values are more abnormal. The local alert threshold uses that behavior; it is not a compromise probability.
- [ClickHouse documents](https://clickhouse.com/docs/engines/table-engines/mergetree-family/mergetree) support time-oriented MergeTree investigation tables and TTL-based retention. Exact keys and TTL must follow real query and retention requirements.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) frames detection within a broader incident-response process. Analyst validation and case tracking are therefore explicit parts of the design.
