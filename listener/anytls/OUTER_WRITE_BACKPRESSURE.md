# Experimental accepted-outer TCP backpressure

Status: HOLD. The default remains off. No production deployment or general performance acceptance is implied.

The server-only `tcp-write-backpressure` option applies Linux TCP_NOTSENT_LOWAT=65536 to each accepted raw outer connection before TLS, including handshake/unauthenticated connections. It returns the original connection, leaves listener/upstream/client/namespace policy unchanged, and preserves the existing TLS/auth/padding/deadline/Close path. Unsupported/failed setup retains the connection and reports at most one asynchronous constant warning. The threshold limits unsent buffering; it is not a hard limit on all SendQ bytes.

Source fc4dcc90 passed34tests/subtests normally and with race, with no skips. The full Go1.25.6 CGO0 with_gvisor CLI SHA4eebf8cad378e9bd088dffe8e100548911819afd08604ed9b3f2e50d914de977 was built and version-checked. The real controlled CLI comparison independently read back accepted fd options: baseline0/inherited versus candidate65536, all other TCP sockets0 and unchanged namespace policy.

The first complete slow-model ABBA group improved loaded-small after-origin-ready median4.711→1.061s and P956.538→1.684s. Bulk remained0.180324→0.180225decimalMB/s; CPU/verifiedMB+2.11%. Independent-small P95 increased0.910→1.148s (+26.25%), failing the frozen5% nonregression gate. The group therefore remainedHOLD and subsequent placement/normal groups were not run. All4trials verified all33responses; this is a latency tradeoff, not a26% request-failure increase. The firstB had a1.389s independent tail versus about0.908–0.911s in the otherthree trials. Sampling noise and shared-bottleneck recovery remain unresolved; no threshold was relaxed or lucky retry used to reverse the verdict.

The comprehensive history, raw-evidence indexes, failures and next actions live in the single [PCS operations ledger](https://github.com/justinchen13/PCS/blob/main/caddy/OPERATIONS.md#round-r20261023-05-close). Keep the oldA5/F1HOLD results; this experiment does not supersede them or justify enabling the option in production.
