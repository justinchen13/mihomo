# R-20261023-03: independent 66-second whole-proxy cost adapter

Root executed all45 pure regression cases: PASS (0.088s). Actual builds/security/cost are still pending.

Prepared source only. No new tests, builds, security trials, Docker or traffic have been run by the author. This is a new candidate and a new workload duration; no R02/S1/S2 PASS is transferred. The original `tools/pcs-stage-history-cost/` at public commit `05bb15f53aeef6e499968441ecd6c59c2d6b1613` is untouched. `UPSTREAM-REUSE.json` lists exact source hashes and which copied files remain byte-identical; `workload-audit.json` records every changed and deliberately unchanged constant.

The inherited chain remains actual verified TLS, AnyTLS authentication and padding, full Mihomo CLI/DIRECT routing, local origin, exact client payload SHA and actual old/new collectors. Both arms enable diagnostics. The same newly built `client-v3.go` binary is used for all arms and profiles. It does not substitute an API microbenchmark for proxy cost.

## Workload and invocation contract

Manifest schema is `history-whole-proxy-cost66-v1`. Required inputs include `execution_mode` (`security` or `matrix`), one integer `selected_profile` (1,32,66), and exactly this workload object (no extra keys, booleans or coerced floats):

```
{"seconds":66,"bulk_bytes":134217728,"upload_bytes":16777216,"small_count":528,"small_bytes":4096}
```

Security requires profile1 and finishes with `SECURITY_PASS`. A matrix invocation runs exactly four new ABBA trials for its selected profile, then writes `complete.json` with `status=PROFILE_PASS` and `profile=n`. It does not run another profile. The external reviewed orchestrator alone decides whether to start the next separately frozen profile; only that orchestrator can aggregate `THREE_PROFILES_PASS`. All four invocations (security,1,32,66) require distinct new output roots and individual manifest hashes. Existing outputs and pooled old results are refused.

Each trial offers 128MiB bulk over66s (2.03360194 decimal MB/s), 16MiB upload and528 small4096B requests (8/s). This preserves the old offered rates, not maximum capacity. Actual downstream verified bytes include bulk + all small bodies + one32B upload digest per outer. Three streams are primed per outer, source IP separation is unchanged, and all raw528 samples remain in `client-result.json`. P95 remains nearest-rank scheduled-to-verified including scheduling/stream wait; rank502 of528 (zero-based501). Runtime rechecks payload/profile identity, sample count/order/body/SHA/success and P95 after the immediate end capture. No successful-sample filtering is permitted to hide failures.

The actual old deadlines were client60s and runner65s. New deadlines are93s (66+27) and98s (93+5), preserving the old margins. Origin request duration cap40→73s and phase cap33→66s prevent rejecting the new valid request. Origin connection180s, origin/anchor240s, ready40s, post-ready GO wait50s,13s warmup, first-second capture,1s settle,8s finish wait and12s collector shutdown grace are unchanged. No timeout is extended after seeing results. The launch bound remains900s +30s TERM cleanup **per invocation**, separate from compilation.

## Unchanged gates and bounded evidence

`numeric_core.py` is byte-identical SHA `69e9da6239de50b7bb9c8cd3307dc4c5cc3f3c95d804d6e929e8f8c5af052554`; it has no workload-size hardcoding. The enclosing adjudicator retains the strict R02 medians: bulk MB/s B/A>=.98, trial P95 B/A<=1.05, proxy and collector CPU per verified MB<=1.20, RSS increase<=16MiB. Every oriented AB/BA pair and dispersion is retained. Baseline collector CPU must be>=.10s per baseline trial, proxy CPU>=.20s per trial. Actual first-second/full parent+proxy quota<=10%, memory high/max/OOM deltas zero, first-second real payload, end-capture skew<=150ms, complete outputs/cursor and cleanup all remain mandatory.

The inherited S1 policy explicitly retains observer-only RESOURCE_INCONCLUSIVE while separately checking comparative collector CPU, full cycle<=10s and normal cadence<=11s. This is not zero observer throttling. No resource/numeric thresholds are relaxed for66s. Unknown fields fail qualification.

All per-tick requests/probes, append attempts and durable ACKs remain individually retained (max2 each/tick); no earlier crop/failure can be hidden by a later good row. Historical capture<=45s requires validated metadata and latest_age<=25s; normal/latest rows retain25s. Historical active records never become current gauges. The narrow old-core freshness view is unchanged and preserves original ages/projection basis. The10s collector cycle, 64KiB response cap, 32 tracked sessions,512 TCP rows, wrapper1MiB/4KiB-record limits and supplied consumer retention/rotation remain unchanged.66s exposes more actual ticks without inventing a new expected count; old minimum3 plus all gap/age/failure predicates remain. Overflow/crop is HOLD, never silently truncated into PASS.

At66 outers with three DIRECT streams, the namespace may contain528 TCP endpoints, exceeding the unchanged512-row snapshot cap. Known omissions remain visible. Whole-proxy payload/cost qualification does not imply full per-socket association, and32 tracked sessions are not66 observed sessions.

## Later reviewed CI use

Use canonical explicit workspace paths only. Supply reviewed full baseline/candidate binaries and source SHA/provenance, old/new flat consumer directories including monitor.py, stage.py, phase_profile.py if required and sibling proxy_rollup.py; every Python dependency is frozen. Production/system paths are refused. Build one client in a separate compile phase:

```
bash tools/pcs-stage-history-cost66/build-client.sh BASELINE_MODULE_SOURCE WORKSPACE/bin/client-v3 WORKSPACE/client-v3-provenance.json
python3 tools/pcs-stage-history-cost66/prepare.py --inputs WORKSPACE/inputs-profile1.json --output WORKSPACE/adapter/manifest-profile1.json
sudo --preserve-env=GITHUB_ACTIONS,GITHUB_WORKSPACE bash tools/pcs-stage-history-cost66/launch.sh MANIFEST_PATH MANIFEST_SHA
```

Go1.25.6/CGO0/readonly module locks and client source+binary provenance are checked. The launch reads mode from the manifest; an explicitly supplied run.py mode must agree. Pre-pull the approved runtime image outside timing and freeze its image ID. Ubuntu24 needs systemd, unified cgroup v2 and Docker's systemd cgroup driver. Parent/proxy .4CPU512MiB, observer .1CPU96MiB, no extra swap, GOMAXPROCS1, network-none owned loopback, no production paths or public requests in timing. Start disk>=1GiB/run floor600MiB, all limits and actual ancestry read back. No retry or automatic deploy.

Original runtime safety/protocol modules and their actual CLI cases are byte-identical. This suite does not separately add an actual CLI history-negative protocol case: exact-source core history-router negative tests, CLI legacy assembly/permissions and the matrix's actual history positive path remain the stated combined coverage.

Cleanup retains exact owner/CID/image/volume/inode proofs and helper description/PID/startticks. A successful stop/kill alone is insufficient: final inactive/MainPID0, original PID identity gone and cgroup absent/empty are required. Unknown cleanup is HOLD. Parent/slice must also be empty before the next arm. Final SIGKILL may bypass Python finally; an unverified ephemeral runner must not be reused. Raw synthetic credentials/certs/keys/private logs are not public artifacts. The parent must preserve all528 safe raw sample fields and all per-tick numeric/enum evidence, not only summary medians or hashes.

## Pure checks prepared, not executed

The original33 pure cases are retained:25 history/cleanup cases byte-identical;7 original threshold/identity tests unchanged and the eighth now checks unchanged numeric core plus explicitly revised client SHA.12 new pure cases cover selected-profile/mode/workload exactness, old contract rejection,528 raw records, payload/P95 identity and deadline/unchanged mechanism constants. Commands for the root reviewer:

```
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/pcs-stage-history-cost66 -p 'test_*.py' -v
bash -n tools/pcs-stage-history-cost66/build-client.sh tools/pcs-stage-history-cost66/launch.sh
```

Author validation is AST/static diff only. All45 new-directory pure results, Go build, real CI resource qualification, full security and all twelve cost trials remain pending. The longer capped workload is intended to give an adequate CPU denominator; it cannot be called a speed improvement.
