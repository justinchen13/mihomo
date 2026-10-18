# S1: bounded class budgets for slow-stage evidence

This is an experimental diagnostic change based on `5f89b59bf00fda9f63f0ddf9ecabf5552d2a2a03`. It has not been deployed. It changes neither the AnyTLS wire protocol nor proxy transport parameters. It does not increase the existing 32-session registry.

Production observation after the 2026-10-18 08:26 UTC release retained 179 fresh publications. Across 173 valid adjacent counter intervals it recorded 9,606 dropped slow events. The existing shared queue did not identify their classes. Retained completed events included 5,157 `read_header` waits, 112 `tls_write` waits and 269 `read_body` waits. Header waits can include idle periods; none of these counts measures failed users or requests.

S1 keeps a total budget of 32 slow events, split into fixed capacities: writer wait 8, writer owned 4, TLS write 8, header read 2, body read 6, pipe write 4. Enqueue remains nonblocking. Each class exposes cumulative attempted, admitted, dropped and dequeued counters. The previous total queue-drop counter is retained. Dequeued means removed from a queue, not successfully delivered. Export/batch loss and 64 KiB payload omissions remain separate. Counter loads are non-atomic; conservation is asserted only after producers are quiescent. Events are sorted by completion time within a publication, without promising a global order across publications.

Reserving capacity can increase the total number of dropped header events and leave another class's slots unused. The intended benefit is preserving evidence of other stages during a header-event flood, not reducing every loss counter.

## Targeted results

The frozen isolated validation ran on 2026-10-18 from 09:04:06.205508 to 09:06:25.662292 UTC. Each Go phase used at most 0.35 CPU, 512 MiB RAM with no extra swap, `GOMAXPROCS=1`, `GOMEMLIMIT=320MiB`, offline modules and `-mod=readonly`. Every phase had a 180-second deadline, a 1 GiB starting disk requirement and a 600 MiB running stop line. Minimum observed free space was 2,110,394,368 bytes. Owned containers were removed and no anonymous volumes were created.

| Test | Result |
| --- | --- |
| Exact old-source pure header-flood negative control | Compiled and executed; failed the intended assertion with header=32, body=0, pipe=0. No compile or resource failure was counted as reproduction. |
| Candidate header flood | PASS: header=2, body=1, pipe=1. |
| Candidate real TLS 1.2 and 1.3 | PASS: exact 4,096-byte DATA and FIN, with TLS-write and queued-writer evidence still present after 64 header events. |
| Six-class capacity, concurrent producers, quiescent accounting and ordering | PASS: total capacity 32, exactly 30 drops for five excess events per class, no replay on the next publication. |
| 64 KiB exporter fallback | PASS: per-class payload omissions remain separate from queue drops. |
| Same four candidate targets under the race detector | PASS, including both TLS versions. |
| Actual production consumer private copy with the proposed patch | 10 pure compatibility/privacy tests PASS. No production consumer was changed. |

No old TLS negative fixture or previously rejected route-blocking fixture was run. These selected race tests do not establish that all Mihomo paths are free of races.

The exact pure negative fixture is saved as `anytls_stage_header_negative_test.go.txt`. Copy it into `transport/anytls/session/s1_header_negative_test.go` in an isolated checkout at the exact baseline and select only `TestStageSlowHeaderFloodCannotConsumeOtherClasses`. It must compile, actually run, and print `S1_COUNTS header=32 body=0 pipe=0`; an unrelated compile/resource failure is not a successful negative control.

## Consumer compatibility and remaining gates

The Unix envelope stays at schema 1. The inner batch becomes schema 2. The existing strict production consumer rejects new inner fields, so the compatible consumer must be validated and installed before enabling the new producer. The proposed consumer accepts old schema 1 and reports its missing class fields as null. Roll back the producer to schema 1 before rolling back to an old consumer.

The exact consumer patch and baseline/candidate hashes are retained beside this document. The patch only changes sanitization; Unix request deadlines, persistent cursor behavior and file-output budgets are unchanged.

Release still requires a full tagged runtime, the applicable security/Unix-route checks and fresh direct-production-to-enabled cost acceptance including the complete collector at 1/32/66 sessions. The earlier 12-run acceptance for the previous producer cannot be inherited. The new class counters and queue allocations need their own enabled cost evidence. The 32-session coverage limit and missing event-time TCP evidence for short-lived connections remain separate follow-up work.

The static next-round plan is `anytls-stage-class-budget-cost-plan.json`. Both arms have diagnostics enabled: A is the current 5f89/schema-1 producer and existing consumer; B includes the new producer and compatible consumer. The former 61f2/OFF/404 baseline cannot be reused. The previous numerical cost gates and workload are retained, but a new exact identity/schema binder and final candidate binary are required before execution. Within-class per-device fairness is not promised by fixed class quotas.

The new fixed metadata can push a nearly full publication over its existing 63 KiB inner budget, causing the existing fallback to omit all session and slow-event details. This remains a release gate. The cost matrix must preserve actual response-byte measurements and report payload limiting, omitted sessions and per-class omitted slow events. An anonymized existing real-TLS lab capture with 32 live plus 32 terminal snapshots is prepared in `fixtures/anytls-stage-full-session.json`; its original identity strings were replaced at equal lengths. Its exact Go serialization/export boundary test has not yet run. Production retained records are sanitized and cannot establish the original wire-body size.

Private validation artifacts are under `/root/proxy-source-lab/loop-20261018/anytls-stage-s1/`. The safe acceptance summary SHA-256 is `691638bc033b08ad487d79b17bd6991883bff9053670230cb3a71057fb2771fd`; source freeze is `91bb2595996f4987a20f398b28f0c0a11b8056af56f6f0a42b14cea7fb2ed054`; execution manifest is `d3ead42dc0c2e09e36323e1b4960a18859a53167578aaf948621fc5333f44455`. The added results document does not change the tested runtime files.

## Publication boundary and tagged build (2026-10-18)

The exact retained TLS fixture contains 32 live and 32 terminal snapshots, rather than 64 tracked live sessions. Four pure-memory cases passed: the observed shape and a declared 32-completion composite, each with small and maximum-width counters. Schema-1/schema-2 inner byte counts were 53,483/53,999; 53,483/54,455; 60,460/60,976; and 60,460/61,432. The largest complete response was 61,602 bytes. All cases fit the unchanged 64,512-byte inner and 65,536-byte response caps without omissions. This is not a bound over every possible active/waiter shape.

The full Go 1.25.6, `with_gvisor`, CGO-disabled, amd64-v1 candidate built successfully from runtime commit `68b13ec2ba57bbb8aafaedae98255636b4fc1bf5`; binary SHA-256 `c8ebac8657434055a64bd3066c8348c86b7171963c6a5f0f583969a2df0524fd`. The build retained production flags and changed Version to `v1.19.17-pcsproxy3`. No image, production deployment or S1 cost matrix was run. The consumer also has a separate 64KiB sanitized-output cap, so wire-size success does not establish end-to-end evidence retention. See the adjacent boundary-results JSON for times, resource readback and cleanup.
