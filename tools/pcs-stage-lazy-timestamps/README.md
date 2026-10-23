# Stage timestamp cost experiment (2026-10-23)

Variant v1 is **HOLD / not deployed**. The queue-full fixture on deployed source allocates two discarded timestamp strings per event; v1 eliminates them by formatting retained events after dequeue. Source operation timestamps, stage/error/frame/byte identity, bounded class accounting and authentication/wire/deadline code remain unchanged.

Frozen BAAB micro cost results (six measurements per variant): dropped event CPU median 398.75 → 54.67 ns, but retained record+collect CPU 947.85 → 1125.50 ns (+18.74%), exceeding the predeclared <=5% regression gate. Event storage grows 128 → 152 bytes. A local diagnostic win is not a public proxy speed claim or release qualification.

Stage tests: 26 top-level +4 subtests pass. Full package normal/race each 38 top-level +11 subtests pass, with the existing opt-in 60-second dead-peer test SKIPPED; therefore these runs do not satisfy the frozen zero-skip full security gate. No skip was suppressed. Two initial tmpfs noexec attempts failed before fixtures, retained separately; corrected baseline-v2 reproduces 2 allocations/event and candidate-v2 passes the zero-allocation fixture.

Normal/race regression and full proxy resource/performance/security gates remain required for any future candidate before rollout. No production parameters or release pins changed. Full evidence and causal limits are indexed in PCS caddy/OPERATIONS.md.

## Variant v2: bounded capacity reservation (HOLD, not deployed)

Preserve the original 128-byte event and accepted-event formatting path. Reserve bounded class capacity using a fixed number of atomic operations before allocating timestamp strings; release on dequeue or failed commit. This does not wait/retry, change wire fields, increase the32-event budget or hide lost events. Capacity includes briefly reserved operations, as documented in source.

Fresh ABBA CPU medians (six samples/variant): discarded event421.95→59.83ns (-85.82%), retained cycle1000.05→1067.50ns (+6.74%). The latter again exceeds the frozen5% gate. Targeted Stage normal/race each26 top-level+4 subtests pass with0 skips. Full v2 security/build/whole-proxy/performance qualification was not run after the early cost failure; v1 tests are not reused as v2 full gates. No runtime settings, binary/image, release pins or live collectors changed.

Both variants remain failed experiments. The original TCP/QUIC stalls are unresolved. The more material current evidence gap is a10s cached-publication/pull timing collision:31 duplicate pulls and forward skipped publications in the fixed30min tail. Its correctness/timing solution is separate future work, not claimed fixed here.
