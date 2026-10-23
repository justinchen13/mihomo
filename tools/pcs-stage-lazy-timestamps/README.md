# Stage timestamp cost experiment (2026-10-23)

Variant v1 is **HOLD / not deployed**. The queue-full fixture on deployed source allocates two discarded timestamp strings per event; v1 eliminates them by formatting retained events after dequeue. Source operation timestamps, stage/error/frame/byte identity, bounded class accounting and authentication/wire/deadline code remain unchanged.

Frozen BAAB micro cost results (six measurements per variant): dropped event CPU median 398.75 → 54.67 ns, but retained record+collect CPU 947.85 → 1125.50 ns (+18.74%), exceeding the predeclared <=5% regression gate. Event storage grows 128 → 152 bytes. A local diagnostic win is not a public proxy speed claim or release qualification.

Stage tests: 26 top-level +4 subtests pass. Full package normal/race each 38 top-level +11 subtests pass, with the existing opt-in 60-second dead-peer test SKIPPED; therefore these runs do not satisfy the frozen zero-skip full security gate. No skip was suppressed. Two initial tmpfs noexec attempts failed before fixtures, retained separately; corrected baseline-v2 reproduces 2 allocations/event and candidate-v2 passes the zero-allocation fixture.

Normal/race regression and full proxy resource/performance/security gates remain required for any future candidate before rollout. No production parameters or release pins changed. Full evidence and causal limits are indexed in PCS caddy/OPERATIONS.md.
