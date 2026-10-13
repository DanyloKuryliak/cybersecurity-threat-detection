# Data and source decision

## Selected real-data study: CTU-13

Source: [Stratosphere Laboratory's CTU-13](https://www.stratosphereips.org/datasets-ctu13), captured at Czech Technical University in 2011. It mixes actual university network activity with botnet traffic generated in controlled lab scenarios. The publisher [lists a Creative Commons Attribution license](https://www.stratosphereips.org/datasets-overview) and asks users to cite Garcia et al., *An empirical comparison of botnet detection methods*, Computers & Security 45 (2014), 100–123. [The dataset FAQ](https://www.stratosphereips.org/datasets-faq) says separate permission is unnecessary when cited. We download only four labeled bidirectional-flow CSVs, never malware binaries or packet payloads. Files and outputs are local and Git-ignored.

| Role | CTU capture | What it does |
| --- | --- | --- |
| Fit | 46, Virut | Known-normal flows only; botnet labels are excluded from fitting |
| Select cutoff | 48, Sogou | Top 5% of host-minute scores; labels are not used to choose the cutoff |
| First test | 52, RBot | Later, different botnet capture; used for the initial reported result |
| Later check | 53 | Added after the original cutoff was fixed; compares transferred alert load and rankings |

Each file has flow timestamp, duration, protocol, source/destination addresses and ports, packet/byte counts, and `Label`. Only labels starting `flow=From-Normal` or `flow=From-Botnet` enter the benchmark. The publisher explicitly cautions that `To-Botnet` means traffic **sent to** an infected computer and is not necessarily malicious. `Background` has unknown status. Neither is recoded as normal. Source IP, destination IP, and `Label` are excluded from model features; local report hosts are aliases. Capture timestamps are local clock times from the files, not asserted to be UTC.

This is a deliberately small, known-origin subset, not the entire network. Training on verified normal flows makes the model a **novelty detector**. Test results estimate how it ranks labeled source-host minutes in these captures. They cannot measure a production false-positive rate across unknown traffic or prove generalization to modern networks. The source files are pinned by SHA-256 in `ctu13.py` and checked before use. Optional Dask Parquet files retain source addresses and labels only in ignored local artifacts; only aliased alert summaries enter the local ClickHouse store. UGR'16 was also inspected: its compact feature release aggregates the whole ISP into one-minute totals, so it does not support the host-level investigation used here.

## Before using approved real data

Document the data owner, collection authority, permitted purpose, license, retention, deletion, and publication rights in a new source decision. Normalize and redact at ingress; validate timestamps and deduplicate IDs. Keep source identifiers access-controlled, encrypt raw storage, and do not put real event records or weights into Git or a public demo. A held-out time period and analyst-reviewed outcomes are required before making detection-performance claims.
