# Stage evidence runtime qualification (2026-10-18)

Source `5f89b59` now has an actual full `with_gvisor` CLI build and off/on functional qualification. **Release remains pending cost acceptance.** No source behavior changed in this documentation commit. The machine's production proxy was not replaced during these tests.

The frozen client creates verified TLS1.3 outer sessions and three real AnyTLS streams per session, validates negotiated padding and exact SHA receipts, and uses fixed paced traffic:64MiB downstream,8MiB upstream and264 small4KiB exchanges over a33s base schedule. Deterministic per-outer phase and actual completion determine the measured window. The unchanged real collector performs API/TCP/log/rollup and optional stage append/cursor fsync, under10percentCPU/96MiB. All traffic processes share a40percentCPU/512MiB parent. Metrics use verified received decimalMB; this is not a maximum-capacity or public-network speed test.

| Trial | Functional/non-resource gates | Original resource verdict | Collector throttled/wall |
|---|---|---|---|
| Off,1 outer | PASS | PASS |4.1834%|
| On,1 outer | PASS | PASS |4.5806%|
| Off,66 outers | PASS | HOLD / RESOURCE_INCONCLUSIVE |12.8018%|
| On,66 outers | PASS | HOLD / RESOURCE_INCONCLUSIVE |15.3543%|

The original observer threshold was10percent throttled/wall. These verdicts are retained. Parent/proxy first-second and full-window throttle were zero; the collector's own quota produced burst delays. At66, both endpoints of lab TCP connections share the namespace:528 socket rows are visible and the regular512 cap omits16. This is a coverage/cost limitation, not permission to waive a failed gate.

Enabled qualification produced three consecutive durable ready records in both profiles, correct epoch/population, no batch or output/cursor failure and zero diagnostic bytes in shared runtime logs. At66,32 live sessions are tracked and34 are explicitly untracked.29 retained socket identities joined the existing monitor by kernel-cookie HMAC; this is not person/device attribution.

The32-example queue fills with ordinary read idle. Across the same32 retained sessions, publication2→4 contains168 new `read_header` slow completions:64 examples survived and104 were dropped, exactly matching `lost_slow_event_total`. Other five stages had zero slow-count increments; each writer stage still recorded695 operations. All per-stage cumulative arrays remained present and monotonic, with no slot churn in that comparison. The34 untracked sessions remain unknown. This proves loss of idle examples in this fixture; it does not prove a writer incident was missed or104 business failures. Normal reads and writer examples share capacity, so later prioritization warrants a separately tested change.

Full CLI security checks passed in both modes: verified TLS1.2/1.3, multiuser/multistream exact payload, settings/padding/FIN, bad authentication/padding/hostname/trust rejection, Unix0700/0600 and a real dropped-UID denial, POST405, and stage-route404 on deliberately enabled private TCP/TLS management listeners. A partial body produced `read_body`, then completed with an exact reply. Missing Unix path, unsafe output and unsafe cursor controls each returned explicit diagnostic failure while the same authenticated stream subsequently returned the correct4096-byte digest. These controls exercise the unchanged stage helper against the live CLI; they do not claim the complete main collector was fault-injected.

A first off66 attempt failed before workload because a test-only warmup reader truncated the larger `/connections` body. The failure is retained. V2 reuses the original monitor4MiB API helper with strict framing completion checks; actual StageReader64KiB/absolute deadline and all workloads/gates stayed unchanged.

Still pending: a separately declared direct comparison of actual production61f2 with stage readerOFF against candidate5f89 with producer/readerON, at1/32/66 outers using ABBA. This measures the proposed deployment combination rather than composing indirect off/on comparisons. Neither qualification single runs nor earlier limited nil-fastpath benchmarks replace those gates. The earlier+25.42percent default-off HOLD also remains recorded. No deployment or public-throughput benefit follows from this document. See `results/20261018-stage-runtime-summary.json` for sanitized numbers; raw identities, paths, credentials and logs are excluded.
