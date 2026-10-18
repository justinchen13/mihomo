# S2: retain slow writer context within the existing 32 observation slots

This is an independent, unvalidated producer candidate based on production
`68b13ec2ba57bbb8aafaedae98255636b4fc1bf5`. It has not been deployed. This change
improves the chance of retaining diagnostic context; it does not change proxy
transport, authentication, TLS, padding, framing, routing, or connection limits.

The current rotating registry can evict a session while its TLS write is blocked.
Its completion then increments `lost_completions` without preserving the stage
context. S2 still takes a free slot first. When all 32 slots are occupied, it
prefers replacing a slot that does not currently contain a writer owner or
tracked writer waiter at least 100 ms old. If all slots contain such writers, it
uses the original rotating fallback. Header, body and pipe waits alone do not
qualify for this preference; this is not a claim that those waits are harmless.

The selected slot stays locked from eligibility inspection through generation
replacement. The existing lock order is hub then slot. The new scan examines at
most 32 free candidates and 32 occupied candidates. No network, logger or JSON
operation runs under this selection lock. DATA observations acquire no new hub
lock. Sampling of different slots is not atomic. A slow writer may still be
lost through all-slow fallback, a previously evicted handle, or later publication
limits. The population remains nonrepresentative; untracked sessions are unknown.

The policy string becomes
`bounded_slow_write_rotation_not_population_sample` in schema 2. Capacities stay
32 live slots, 32 terminal records and 32 classified slow events. Publication
stays every 10 seconds with the existing 64 KiB limit. Existing eviction and lost
completion accounting is retained. Already-evicted handles are not re-admitted;
work begun after eviction is not exhaustively counted by `lost_completions`.

## Verification status

Only formatting and consumer tests have run locally. On 2026-10-18 at
11:32:12.826202–11:32:30.458218 UTC, the owned formatter exited successfully and
was removed. Formatting changed no bytes. Sixteen pure consumer tests passed in
the 10% CPU / 96 MiB / no-swap unit. They check old schema 1/2 compatibility, the
new schema 2 policy, fixed-field rejection, and four existing legal dense shapes
through the actual bounded writer and durable cursor, including rotation states.
The new consumer is not installed. Results are in
`results/20261018/stage-admission-consumer-local.json`.

The producer tests are prepared, not executed:

* `TestStageAdmissionPreservesSlowWriterDuringAuthChurn` is copied unchanged to
  old 68b13 as a negative control. It must compile, run the exact test, and fail
  with `status=untracked completed=0 lost=1`. A compile or resource failure is not
  a successful negative control. The candidate must retain the original context
  and completion while preserving the 32-slot accounting.
* Three further tests cover exact age boundaries, free-first/all-slow rotation,
  and concurrent generation checks, close, observation and collection. Candidate
  normal and race runs remain required.
* `BenchmarkStageAdmissionChurn` is an identical pure-memory fixture for old and
  candidate code, with idle, one-slow-writer and all-slow 32-slot cases. It reports
  process CPU microseconds/op and allocations. It does not model network speed.

Remote CI is being prepared for independent review. It must exclude the earlier
route/listener fixtures, verify unchanged dependency locks, build with pinned
Go 1.25.6 and `with_gvisor`, and preserve every failing result. No remote workflow
has been triggered for this candidate at this point.

## Integration and rollback boundaries

The consumer must first accept both admission policy strings and retain the
policy in sanitized output. The old consumer rejects the new policy, so producer
rollout must follow consumer compatibility deployment. Roll back the producer
first; the dual-policy consumer can stay in place. Never infer healthy untracked
sessions or exact population coverage from a retained slow context.

Before deployment, measure the complete producer plus same consumer using a new
fixed matrix, including publication bytes/omissions, per-class queue counters,
all-slow fairness and exact resource usage. Previous S1 cost results do not cover
this added admission scan. A pure admission benchmark is only a diagnostic cost
check, not a substitute for that deployment gate.
