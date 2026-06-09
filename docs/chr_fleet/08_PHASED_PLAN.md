# 08 — Phased Execution Plan (with File Ownership)

> The build plan future implementation agents follow. Phases are ordered so each
> depends only on earlier ones. **Within a phase, every task lists the exact files
> it owns** — no two tasks in the same phase touch the same file, so parallel
> agents never collide on a merge. Each phase has acceptance criteria + a test
> strategy.

---

## 8.0 Conventions

- **Repos:** `P` = `radius-proxy`, `A` = `radius-module-admin` (panel), `M` =
  `radius-module`. A task's files are prefixed with the repo.
- **New files are preferred over edits** to maximize parallelism; where an edit to
  a shared existing file is unavoidable (e.g. wiring), it is isolated to **one**
  task in the phase (the "integrator" task) so only that agent touches it.
- "Agents" = independent implementation workers that can run concurrently within
  the phase. The recommended count is the **max number that never share a file**.
- Each phase ends with a merge gate: all tasks merged + acceptance criteria green.

```mermaid
flowchart LR
  P1[P1 Design freeze] --> P2[P2 Data/migrations]
  P2 --> P3[P3 Registry+Onboarding]
  P3 --> P4[P4 Monitoring/Health+Telemetry]
  P4 --> P5[P5 Scoring/Placement]
  P5 --> P6[P6 Front-door DNS]
  P6 --> P7[P7 Live apply + CoA]
  P7 --> P8[P8 Failover/Rebalance]
  P8 --> P9[P9 Notifications]
  P9 --> P10[P10 Hardening]
```

---

## Phase 1 — Design freeze & scaffolding
**Goal:** lock contracts + create empty module skeletons so later phases never
fight over file creation.

| Task | Owns (files) | Repo |
|---|---|---|
| P1-T1 Contract freeze | `A:docs/contracts/fleet_api.md` (telemetry, placement, coa, fleet/* shapes) | A |
| P1-T2 Config tunables skeleton | `A:fleet/config.py` (all §5.8 tunables, empty defaults) | A |
| P1-T3 Proxy module stubs | `P:telemetry.py`, `P:placement_hook.py`, `P:coa.py` (empty classes + docstrings only) | P |
| P1-T4 Panel package skeleton | `A:fleet/__init__.py`, `A:fleet/registry/__init__.py`, `A:fleet/health/__init__.py`, `A:fleet/brain/__init__.py`, `A:fleet/dns/__init__.py`, `A:fleet/control/__init__.py`, `A:fleet/notify/__init__.py` | A |

- **Agents: 4** (T1–T4 touch disjoint files).
- **Acceptance:** repo imports cleanly; contracts doc reviewed by owner.
- **Tests:** import smoke test in each repo CI.

---

## Phase 2 — Data model & migrations
**Goal:** all tables exist. (Schema = [02](02_DATA_MODEL.md).)

| Task | Owns (files) | Repo |
|---|---|---|
| P2-T1 providers + chr_nodes | `A:migrations/001_providers_chr_nodes.sql`, `A:fleet/registry/models_chr.py` | A |
| P2-T2 metrics + health | `A:migrations/002_metrics_health.sql`, `A:fleet/health/models_health.py` | A |
| P2-T3 users + sessions + decisions | `A:migrations/003_users_sessions.sql`, `A:fleet/brain/models_session.py` | A |
| P2-T4 events + alerts | `A:migrations/004_events_alerts.sql`, `A:fleet/notify/models_alert.py` | A |
| P2-T5 onboarding + dns_state | `A:migrations/005_onboarding_dns.sql`, `A:fleet/registry/models_onboarding.py`, `A:fleet/dns/models_dns.py` | A |
| P2-T6 fixed-IP contract in M | `M:docs/fixed_ip_contract.md`, `M:radius/fixed_ip.py` (deterministic Framed-IP allocator + UNIQUE) | M |

- **Agents: 6** (5 disjoint migration files + models; T6 is a different repo).
- **Acceptance:** migrations apply up+down cleanly on a fresh DB; `chr_effective`
  view returns resolved cost/cap; `M` allocator returns a stable IP per user and
  rejects duplicates.
- **Tests:** migration round-trip test; model CRUD unit tests; allocator
  idempotency + uniqueness test.

---

## Phase 3 — Registry + Onboarding wizard
**Goal:** owner can add a CHR via the wizard; panel generates keys + the unified
script and reaches `pushed`. (= [06](06_ONBOARDING_WIZARD.md).)

| Task | Owns (files) | Repo |
|---|---|---|
| P3-T1 Wizard API + state machine | `A:fleet/registry/onboarding_service.py`, `A:fleet/registry/routes_onboarding.py` | A |
| P3-T2 WireGuard key/secret generation | `A:fleet/registry/wg_keys.py`, `A:fleet/registry/secrets_vault.py` | A |
| P3-T3 RouterOS script renderer | `A:fleet/registry/script_render.py`, `A:fleet/registry/templates/chr_unified.rsc.j2` | A |
| P3-T4 Bootstrap pusher (one-time channel) | `A:fleet/registry/bootstrap_push.py` | A |
| P3-T5 Registry CRUD API + UI | `A:fleet/registry/routes_chr.py`, `A:fleet/ui/onboarding_wizard.*` (frontend) | A |
| P3-T6 Provider CRUD | `A:fleet/registry/routes_provider.py`, `A:fleet/registry/provider_service.py` | A |

- **Agents: 6** (all disjoint files; T1 calls T2/T3/T4 via interfaces defined in P1).
- **Acceptance:** submitting the wizard creates `chr_nodes`+`onboarding_jobs`
  rows, generates a keypair (public key stored, private vault-ref'd), renders a
  valid `.rsc` differing only in bindings, and reaches `pushed`.
- **Tests:** render two CHRs → diff is **only** the 4 binding vars; vault never
  stores plaintext; state machine transition tests; RouterOS script lints against
  a syntax checker / mock.

---

## Phase 4 — Monitoring, health & telemetry
**Goal:** every CHR is pinged + sampled; proxy reports per-CHR telemetry and
placement; health state machine populated. (= [03](03_FRONT_DOOR_DNS.md) §3.4, [05](05_LOAD_BALANCER_BRAIN.md) §5.5.)

| Task | Owns (files) | Repo |
|---|---|---|
| P4-T1 ICMP/probe health loop | `A:fleet/health/probe_loop.py`, `A:fleet/health/health_state.py` (hysteresis machine) | A |
| P4-T2 Control-plane metrics collector | `A:fleet/control/routeros_client.py`, `A:fleet/health/metrics_collector.py` | A |
| P4-T3 Telemetry ingest API | `A:fleet/registry/routes_telemetry.py` (`/api/proxy/telemetry`), `A:fleet/health/telemetry_ingest.py` | A |
| P4-T4 Placement ingest API | `A:fleet/brain/routes_placement.py` (`/api/proxy/placement`), `A:fleet/brain/placement_ingest.py` | A |
| P4-T5 Proxy telemetry emitter | `P:telemetry.py` (fill stub) | P |
| P4-T6 Proxy placement hook | `P:placement_hook.py` (fill stub) | P |
| P4-T7 Proxy wiring (integrator) | `P:proxy.py` (call telemetry/placement on acct), `P:config.py` (new env vars), `P:routing_table.py` (per-CHR counters) | P |

- **Agents: 6 in parallel + 1 serial integrator.** T1–T6 are disjoint; **P4-T7 is
  the only task that edits existing proxy files** (`proxy.py`, `config.py`,
  `routing_table.py`) and runs **after** T5/T6 land, alone, to avoid collisions.
- **Acceptance:** a DOWN CHR transitions per hysteresis (~5 min); `chr_metrics`
  fills every interval; proxy posts telemetry + placement; `sessions` reflects
  real Acct-Start/Stop.
- **Tests:** simulated ping-loss → state transitions honor `DOWN_AFTER`/`UP_AFTER`/
  cooldown; telemetry/placement endpoint contract tests; proxy integration test
  with a fake CHR + fake RADIUS.

---

## Phase 5 — Scoring brain & placement engine
**Goal:** every CHR has a live score; new-connection fill order + rebalance
candidates computed (not yet actuated). (= [05](05_LOAD_BALANCER_BRAIN.md).)

| Task | Owns (files) | Repo |
|---|---|---|
| P5-T1 Score function | `A:fleet/brain/scoring.py` (all §5.2 factors, pure functions) | A |
| P5-T2 Bandwidth accounting | `A:fleet/brain/usage_accounting.py` (counter-reset/billing-cycle logic, §5.3) | A |
| P5-T3 Fill-order + placement planner | `A:fleet/brain/placement_planner.py` (eligible set, open-first, top-N) | A |
| P5-T4 Rebalance planner (no actuation) | `A:fleet/brain/rebalance_planner.py` (candidate moves, margins, batch caps) | A |
| P5-T5 Brain scheduler tick | `A:fleet/brain/scheduler.py` (every SCORE_INTERVAL: score→persist) | A |

- **Agents: 5** (disjoint pure modules; scheduler composes them via imports).
- **Acceptance:** worked example ([05](05_LOAD_BALANCER_BRAIN.md) §5.7) reproduces the
  documented scores ±1; fill order = open-first; rebalance proposes moves only
  above `REBALANCE_MARGIN`.
- **Tests:** table-driven unit tests for every penalty curve with the documented
  numeric examples; property test "down/disabled/over-cap never placed".

---

## Phase 6 — Front-door DNS integration
**Goal:** healthy set published to `vpn.hoberadius.com`, edge-triggered. (= [03](03_FRONT_DOOR_DNS.md).)

| Task | Owns (files) | Repo |
|---|---|---|
| P6-T1 DNS provider driver(s) | `A:fleet/dns/providers/cloudflare.py`, `A:fleet/dns/providers/base.py` | A |
| P6-T2 DNS controller (diff + publish) | `A:fleet/dns/dns_controller.py` (compute healthy set, diff vs `dns_records_state`, empty-set guard) | A |
| P6-T3 DNS bias for moves | `A:fleet/dns/dns_bias.py` (drain source / prefer target windows, §[07](07_CONTROL_PLANE.md) §7.7) | A |
| P6-T4 DNS scheduler wiring | `A:fleet/dns/dns_scheduler.py` (subscribe to health/score changes) | A |
| P6-T5 PowerDNS/Route53 drivers (optional parallel) | `A:fleet/dns/providers/powerdns.py`, `A:fleet/dns/providers/route53.py` | A |

- **Agents: 5** (each driver + controller + bias + scheduler are disjoint files).
- **Acceptance:** marking a CHR DOWN removes its IP from DNS within one tick;
  never publishes empty; only calls the API when the set changes; top-8 cap
  honored.
- **Tests:** mock provider API; assert diff-only calls; empty-set guard test;
  failover-window bias test.

---

## Phase 7 — Live apply + CoA (kill-old-session, disconnect)
**Goal:** the panel can actually disconnect/move a session. (= [04](04_FIXED_IP_AND_SESSIONS.md), [07](07_CONTROL_PLANE.md).)

| Task | Owns (files) | Repo |
|---|---|---|
| P7-T1 Proxy CoA sender | `P:coa.py` (fill stub: RFC 5176 Disconnect/CoA build+send) | P |
| P7-T2 Proxy CoA endpoint (integrator) | `P:proxy.py` (add `/api/proxy/coa` handler path / control listener), `P:main.py` (start CoA service) | P |
| P7-T3 Panel CoA requester | `A:fleet/control/coa_client.py` (calls `/api/proxy/coa` w/ idempotency) | A |
| P7-T4 Control orchestrator | `A:fleet/control/orchestrator.py` (queue, retries, per-CHR serialize) | A |
| P7-T5 Command API surface | `A:fleet/control/routes_command.py` (`/api/fleet/chr/{id}/command`) | A |
| P7-T6 Kill-old-session logic | `A:fleet/brain/session_guard.py` (detect reconnect, trigger CoA on old) | A |
| P7-T7 M: accept CoA | `M:docs/coa_requirements.md` + FreeRADIUS/RouterOS CoA enablement notes | M |

- **Agents: 6 parallel + 1 serial integrator.** P7-T2 is the **only** task editing
  existing `proxy.py`/`main.py`; it runs alone after P7-T1.
- **Acceptance:** a 2nd login for a user on a different CHR reliably disconnects
  the old session (Disconnect-ACK) within seconds; idempotent replays are no-ops;
  DB ends with exactly one active session.
- **Tests:** integration with two fake CHRs; verify single-survivor invariant;
  CoA timeout path (old CHR down) closes the stale row.

---

## Phase 8 — Failover & rebalance actuation
**Goal:** turn the planners (P5) + actuators (P6/P7) into automatic behavior. (= [05](05_LOAD_BALANCER_BRAIN.md) §5.6.)

| Task | Owns (files) | Repo |
|---|---|---|
| P8-T1 Forced-failover executor | `A:fleet/brain/failover_executor.py` (on DOWN: headroom check → evacuate-all → DNS + CoA) | A |
| P8-T2 Rebalance executor | `A:fleet/brain/rebalance_executor.py` (movable-only, batch, margins) | A |
| P8-T3 Capacity headroom guard | `A:fleet/brain/headroom_guard.py` (fleet headroom alert, §5.6.4) | A |
| P8-T4 Thundering-herd controls | `A:fleet/brain/herd_controls.py` (spread via top-N DNS + staggered batches) | A |
| P8-T5 Executor wiring (integrator) | `A:fleet/brain/scheduler.py` (hook executors into the tick) | A |

- **Agents: 4 parallel + 1 serial integrator** (P8-T5 alone edits `scheduler.py`
  again, after T1–T4).
- **Acceptance:** killing a CHR in a test fleet → all its users (incl.
  `movable=false`) land on healthy CHRs with their fixed IPs; insufficient
  headroom raises CRIT + does not over-pack one node; normal rebalance moves
  **only** movable users.
- **Tests:** chaos test (down a node) asserts forced failover + same-IP reconnect;
  movable-flag respected in rebalance but overridden in failover; headroom alert
  fires when fleet can't absorb its biggest node.

---

## Phase 9 — Notifications
**Goal:** owner gets SMS/WhatsApp/Telegram on DOWN/failover/cap events, deduped.
(Uses the messaging layer being built in `radius-module-admin`.)

| Task | Owns (files) | Repo |
|---|---|---|
| P9-T1 Notifier core + dedupe | `A:fleet/notify/notifier.py` (consume `alerts`, dedupe_key suppression) | A |
| P9-T2 Channel adapters | `A:fleet/notify/channels/sms.py`, `.../whatsapp.py`, `.../telegram.py` | A |
| P9-T3 Event→alert rules | `A:fleet/notify/alert_rules.py` (which events alert, severity, throttle) | A |
| P9-T4 Owner report generator | `A:fleet/notify/reports.py` (failover post-mortem report, §[05](05_LOAD_BALANCER_BRAIN.md)) | A |
| P9-T5 Metrics retention job | `A:fleet/health/retention_job.py` (downsample `chr_metrics`, §[02](02_DATA_MODEL.md)) | A |

- **Agents: 5** (channel adapters are 3 disjoint files; rest disjoint).
- **Acceptance:** a DOWN event delivers exactly one message per channel; storms
  collapse via `dedupe_key`; failover produces a report row.
- **Tests:** mock gateways; dedupe-window test; rule-matrix unit tests.

---

## Phase 10 — Hardening & ops
**Goal:** production-grade security, key rotation, observability, runbooks.

| Task | Owns (files) | Repo |
|---|---|---|
| P10-T1 Token replay protection | `A:fleet/security/token_guard.py` (nonce cache + window for `X-Proxy-Token`) | A |
| P10-T2 Per-CHR secret option | `P:routing_table.py` (+per-CHR secret map), `P:config.py` (flag) — **integrator, alone** | P |
| P10-T3 WG key rotation | `A:fleet/control/key_rotation.py` | A |
| P10-T4 Observability dashboards | `A:fleet/ui/dashboards.*`, `A:docs/runbooks/fleet_ops.md` | A |
| P10-T5 Chaos/load test harness | `A:tests/fleet/chaos/*`, `P:tests/test_coa.py` | A+P (disjoint dirs) |
| P10-T6 Security review pass | `A:docs/security/fleet_threat_model.md` | A |

- **Agents: 5** (T2 is the only one editing existing proxy files; it stands alone
  in the proxy repo while others work in the panel).
- **Acceptance:** replayed tokens rejected; keys rotate without downtime; chaos
  suite green; threat model signed off.
- **Tests:** replay test; rotation integration test; full chaos run.

---

## 8.1 File-ownership matrix (collision proof)

The only **existing** files ever edited are isolated to single "integrator" tasks,
each running alone within its phase:

| Existing file | Edited only by | Phase |
|---|---|---|
| `P:proxy.py` | P4-T7, then P7-T2 (never concurrently) | P4, P7 |
| `P:config.py` | P4-T7, then P10-T2 | P4, P10 |
| `P:routing_table.py` | P4-T7, then P10-T2 | P4, P10 |
| `P:main.py` | P7-T2 | P7 |
| `A:fleet/brain/scheduler.py` | P5-T5, then P8-T5 (sequential phases) | P5, P8 |
| `A:fleet/config.py` | P1-T2 (created), read-only thereafter | P1 |

Everything else is a **new file owned by exactly one task**. Because integrators
are scheduled alone, **no two concurrent agents ever share a file** → no merge
collisions by construction.

---

## 8.2 Recommended agents per phase (summary)

| Phase | Parallel agents | Note |
|---|---|---|
| P1 | 4 | disjoint scaffolds |
| P2 | 6 | 5 migrations + M allocator |
| P3 | 6 | wizard subsystems |
| P4 | 6 + 1 serial | integrator P4-T7 runs alone |
| P5 | 5 | pure scoring modules |
| P6 | 5 | DNS drivers + controller |
| P7 | 6 + 1 serial | integrator P7-T2 runs alone |
| P8 | 4 + 1 serial | integrator P8-T5 runs alone |
| P9 | 5 | notify subsystems |
| P10 | 5 | T2 alone in proxy repo |

"+ 1 serial" = the integrator task that edits a shared existing file; it merges
**after** the phase's parallel tasks, alone, so it never races them.

---

## 8.3 Cross-phase test strategy

| Level | What | When |
|---|---|---|
| Unit | pure functions (scoring, hysteresis, usage) | every phase |
| Contract | API request/response shapes vs [01](01_ARCHITECTURE.md) §1.4 | P3–P9 |
| Integration | proxy ↔ fake CHR ↔ fake RADIUS; panel ↔ fake CHR | P4, P7 |
| Chaos | down a node / down a provider; assert failover + same-IP | P8, P10 |
| Load | thundering-herd reconnect; capacity headroom | P8, P10 |
| Security | token replay, secret isolation, wg-mgmt no-data-route | P10 |

A staging fleet of **≥3 real CHRs across ≥2 providers** is required for P8/P10
chaos validation — see [09](09_OWNER_INPUTS_AND_RISKS.md).
