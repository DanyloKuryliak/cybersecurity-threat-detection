# Delivery plan

Goal: a credible, reviewable study of network threat detection using public labeled traffic, with a documented path to a production service. Checkboxes mean verified work, not intended work.

## Acceptance criteria for repository preparation

- [x] Choose a lawful source and define an event, feature, and label contract.
- [x] Build and evaluate a local detector on labeled public network-flow captures.
- [x] Document production components, failure paths, security controls, and public-release limits.
- [x] Run the documented unit, lint, and smoke commands and record the result in the handoff.

## Stage 1 — trustworthy local baseline

- [x] Establish an Isolation Forest baseline on real labeled flow captures.
- [x] Select and download a cited, licensed CTU-13 subset; verify source hashes, schema, label semantics, and capture order.
- [x] Fit on one capture's known-normal flows, set a review cutoff on a later capture without labels, and evaluate on a third capture. Show both wins and failures in a local report.
- [x] Compare the model's host-minute queue with a simple ICMP rule and document what each misses.
- [x] Compare the validation cutoff with a fixed 5% batch review budget on later captures 52 and 53. Report precision, recall, alerts per capture hour, and delay for detected botnet sources.

## Stage 2 — larger local research system

- [x] Add an explicitly licensed or permissioned dataset with a written source decision and field mapping. Keep raw data out of Git.
- [x] Add an optional Dask-to-Parquet backfill with row-count reconciliation. The current captures fit in memory, so it is a scale exercise, not a measured speedup.
- [x] Train a PyTorch autoencoder challenger from known-normal flows. Save its schema, preprocessing, source and code hashes, ignored weights, and evaluation report. Keep Isolation Forest because the challenger did not win at the small fixed review budget.
- [x] Add local ClickHouse for aliased alert investigation, with repeatable derived-data loads, 30-day retention from load time, and count reconciliation.
- [x] Add a localhost FastAPI service and analyst page for search, alert details, and versioned review notes.

## Future production work — conditional on an authorized organization

The public repository is complete as a local research project. These items are a deployment design, not unfinished parts of the local deliverable:

- [ ] Agree on owner, authorized sensors, threat model, data classification, retention, and incident response process.
- [ ] Add durable ingest/replay and test late or duplicate events, empty windows, schema changes, and missing data against an authorized source.
- [ ] Validate replay throughput, queue lag, end-to-end latency, recovery from worker/database outages, and backfill parity against written targets.
- [ ] Add authenticated role-based access, audit trails, encryption, secrets management, backups, and retention enforcement.
- [ ] Calibrate thresholds using analyst-reviewed outcomes; monitor drift, false-positive load, model/feature versions, and missing telemetry. Shadow-run before enabling alerts. Human analysts decide response; no automatic blocking from an anomaly score.
- [ ] Review deployment, public claims, and data exposure before enabling any external service.

## Initial production targets to validate with an operator

Proposed targets are **design assumptions**, not measured results: 99% of accepted events visible to investigation within 2 minutes; no silent event loss; replay idempotent by `event_id`; a degraded model falls back to rules/ingestion visibility; and the alert budget is set by the actual analyst team. Measure the achievable values on the chosen source before committing to an SLO.
