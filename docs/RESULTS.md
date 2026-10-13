# CTU-13 research result

Question: can a detector trained on known-normal traffic from one capture rank botnet activity in different captures while keeping an analyst's alert queue manageable?

Four [official CTU-13 bidirectional-flow files](https://www.stratosphereips.org/datasets-ctu13) were downloaded and SHA-256 checked. Isolation Forest and a PyTorch autoencoder use the same 12 flow features, without IP addresses or labels. Both fit on capture 46 known-normal flows. Capture 48 sets each model's 95th-percentile host-minute alert cutoff **without labels**. Captures 52 and 53 are later checks. Only `From-Normal` and `From-Botnet` rows enter the benchmark. The optional Dask backfill reproduces their row counts in ignored Parquet files.

| Capture | All flows | Known-origin flows | Botnet host-minutes | Isolation Forest alerts | Botnet minutes found |
| --- | ---: | ---: | ---: | ---: | ---: |
| 46: fit | 129,832 | 5,561; 4,660 normal used for fit | — | — | — |
| 48: cutoff | 114,077 | 1,732 | 5 | 3 | 0 |
| 52: first test | 107,251 | 10,873 | 11 | 8 | 5 |
| 53: later check | 325,471 | 9,783 | 105 | 97 | 85 |

The transferred cutoff produced **8 alerts in 17 minutes** on capture 52 and **97 alerts in 74 minutes** on capture 53. On capture 53, 85 of 105 labeled botnet host-minutes were found, but the queue grew to 78.65 alerts per capture hour. That is far above the 8.18 alerts per hour on validation. It still missed all five botnet minutes in validation. The threshold is therefore unstable across captures.

| Model and policy | Capture 52 alerts / botnet minutes found | Capture 53 alerts / botnet minutes found |
| --- | ---: | ---: |
| Isolation Forest, validation cutoff | 8 / 5 | 97 / 85 |
| PyTorch autoencoder, validation cutoff | 16 / 7 | 104 / 93 |
| Isolation Forest, top 5% batch budget | 3 / 2 | 13 / 13 |
| PyTorch autoencoder, top 5% batch budget | 3 / 1 | 13 / 13 |
| Simple any-ICMP rule | 12 / 5 | 13 / 7 |

At the same small review budget, the PyTorch model found fewer botnet minutes on capture 52 and the same number on capture 53. Its ranking average precision was also lower: **0.459 versus 0.554** on capture 52 and **0.931 versus 0.955** on capture 53. It is saved as a local challenger, not promoted. The top-5% policy is a **retrospective batch ranking**, because it needs every host-minute in the capture before choosing the alerts; it cannot directly serve as a live cutoff.

All metrics cover only the selected known-origin subset. `Background` and `To-Botnet` traffic has uncertain binary status and is excluded, so these are not production false-positive rates. All captures are short and from 2011. The fourth capture was added after the original Isolation Forest design; its use for the later PyTorch comparison is exploratory, not an untouched final test. The local API shows benchmark labels for research, while analyst review notes are separate. No current organization's traffic or analyst outcomes have been evaluated.

Reproduce with `uv run threat-ctu13-download`, `uv run threat-ctu13-evaluate`, then the optional Docker research commands in the [README](../README.md). Exact counts and per-alert rows are in ignored local reports under `artifacts/ctu13/`. Dataset credit and label decisions are in [DATA.md](DATA.md).
