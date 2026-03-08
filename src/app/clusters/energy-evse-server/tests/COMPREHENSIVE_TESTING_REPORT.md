# Energy EVSE Cluster (9.3) — Comprehensive Testing Report

**Specification:** Matter 1.5 Application Cluster Specification, Section 9.3 (Pages 716–742)  
**Cluster ID:** 0x0099  
**PICS Code:** EEVSE  
**Safety Class:** SAFETY_CRITICAL — high-current electrical energy transfer, V2X grid backfeed  
**Date:** 2025-03-09  
**Branch:** `v1.5_energyevsecluster_test`

---

## Executive Summary

The vulnerability analysis identified **7 VIOLATED properties** out of 39 total. After defense analysis, **5 were DISPROVED** and **2 were CONFIRMED VALID**. All 2 VALID vulnerabilities were verified through real SDK attack simulation against production `EnergyEvse::Instance` code.

| Metric | Count |
|---|---|
| Total properties analyzed | 39 |
| HOLDS (confirmed secure) | 32 |
| VIOLATED (originally claimed) | 7 |
| DISPROVED by defense | 5 |
| **CONFIRMED VALID** | **2** |
| E2E tests written | 13 |
| SpecGap tests written | 10 |
| **Total tests** | **23** |
| **Tests passing** | **23/23** |

---

## VALID Vulnerabilities — Attack Simulation Results

### PROP_EVSE_011 — Diagnostics DoS via Unbounded Duration (HIGH)

**Claim:** StartDiagnostics has no maximum duration, no cancellation command, and uses Operate privilege (same as EnableCharging). An Operate-level attacker can hold the EVSE in DisabledDiagnostics indefinitely, blocking all charging.

**SDK Evidence:**
- `HandleStartDiagnostics()` delegates directly to `mDelegate.StartDiagnostics()` with zero guardrails
- Delegate checks only `mSupplyState != Disabled` → if Disabled, sets `SupplyState = DisabledDiagnostics`
- `CheckFaultOrDiagnostic()` returns `Failure` when `mSupplyState == kDisabledDiagnostics`, which blocks both `EnableCharging` and `EnableDischarging`
- No `CancelDiagnostics` command exists (only 7 commands: 0x01–0x07)
- No `MaxDiagnosticsDuration` attribute exists
- StartDiagnostics metadata: `Privilege::kOperate` + `kTimed` — identical to EnableCharging

**E2E Attack Simulation (7 tests, all PASS):**

| Test | Attack Scenario | Result |
|---|---|---|
| `PROP011_StartDiagnosticsFromDisabled` | Send StartDiagnostics from Disabled state | Success → DisabledDiagnostics |
| `PROP011_StartDiagnosticsRejectedWhenCharging` | Send from ChargingEnabled state | Correctly rejected (Failure) |
| `PROP011_EnableChargingBlockedDuringDiagnostics` | Enter diagnostics → try EnableCharging | **EnableCharging BLOCKED — DoS confirmed** |
| `PROP011_EnableDischargingBlockedDuringDiagnostics` | Enter diagnostics → try EnableDischarging (V2X) | **V2X also BLOCKED** |
| `PROP011_RepeatedDiagnosticsDoSLoop` | Diagnostics → complete → re-enter → EnableCharging | **Infinite DoS loop confirmed** |
| `PROP011_DisableCommandDuringDiagnostics` | Disable during diagnostics → re-enter diagnostics | **Disable exits diag but attacker re-enters immediately** |
| `PROP011_DiagnosticsAndChargingUseSamePrivilege` | Verify both commands accepted with Operate privilege | **Privilege asymmetry confirmed** |

**Verdict: VALID — Spec gap confirmed in SDK implementation**

The attack cycle is:
1. Attacker sends `StartDiagnostics` (Operate + Timed) when EVSE is Disabled
2. EVSE enters `DisabledDiagnostics` — all charging/discharging commands fail
3. Diagnostics run for manufacturer-defined duration (NO MAXIMUM)
4. When complete, SupplyState returns to Disabled
5. Attacker immediately re-sends StartDiagnostics → infinite loop

---

### PROP_EVSE_036 — Time Synchronization Dependency for Epoch Attributes (MEDIUM)

**Claim:** The EVSE depends on `ChargingEnabledUntil` / `DischargingEnabledUntil` (epoch_s) for session expiry enforcement, but contains no time source integrity checks, no rollback detection, and no fallback behavior.

**SDK Evidence:**
- `EnableCharging` handler validates min/max current constraints but performs **zero validation on the epoch value**
- Past values (epoch=1), zero values (epoch=0), and arbitrarily large values (epoch=4000000000) are all accepted
- Null values mean indefinite charging — no time boundary at all
- `HandleEnabledStateExpiration()` uses `IsTimeExpired(timeValue, currentTime)` where `currentTime` comes from system clock with no integrity checking
- No `TimeSourceQuality`, `TimeSourceStatus`, or similar attribute exists in the cluster
- The cluster has no mechanism to detect time rollback or time jump

**E2E Attack Simulation (6 tests, all PASS):**

| Test | Attack Scenario | Result |
|---|---|---|
| `PROP036_ChargingEnabledUntilAcceptsEpochValue` | Set valid future epoch | Accepted — no time source check |
| `PROP036_NullChargingEnabledUntilMeansIndefinite` | Set null → indefinite charging | Accepted — no time boundary |
| `PROP036_DischargingEnabledUntilAcceptsEpochValue` | Set V2X discharge epoch | Accepted — V2X also vulnerable |
| `PROP036_PastEpochValueAccepted` | Set epoch=1 (year 2000) | **Accepted — past time NOT rejected** |
| `PROP036_ZeroEpochValueAccepted` | Set epoch=0 (already expired) | **Accepted — no expiry validation** |
| `PROP036_LargeEpochValueAccepted` | Set epoch=4000000000 (~year 2126) | **Accepted — no upper bound** |

**Verdict: VALID — Spec gap confirmed in SDK implementation**

Attack vectors:
1. **Time rollback:** Compromise NTP/Time Sync cluster → roll clock back → `ChargingEnabledUntil` never fires → session extends indefinitely
2. **Past epoch injection:** Set `ChargingEnabledUntil=1` → session immediately expired → unexpected charging termination
3. **Indefinite charging:** Set null → no boundary → charging continues until physical disconnect

---

## DISPROVED Vulnerabilities — Defense Verification

### PROP_EVSE_001 — All Commands Require Timed Invoke → **DISPROVED**

The vulnerability analysis claimed the FSM model lacked Timed Invoke enforcement. The SDK's generated `Metadata.h` proves all 7 commands have `CommandQualityFlags::kTimed`:

```
SpecGap test: DISPROVED_001_AllCommandsRequireTimedInvoke → PASS
All 7 commands (Disable, EnableCharging, EnableDischarging, StartDiagnostics,
SetTargets, GetTargets, ClearTargets) have kTimed flag set.
```

This was an FSM modeling error, not a specification gap. The spec correctly mandates "O T" for all commands.

### PROP_EVSE_007 — Physical Safety Lockout → **DISPROVED**

The spec's "MAY lockout" refers to an *additional* software-layer lockout on top of mandatory J1772/IEC61851 hardware safety protocols. The Matter cluster assumes hardware safety as mandatory infrastructure (Section 9.3 intro). Not testable at SDK level — hardware protocol is external.

### PROP_EVSE_008 — GFCI/CCID Fault Physical Clearance → **DISPROVED**

FaultState (0x0002) has `R V` access — read-only. Verified in SpecGap test:
```
SpecGap test: DISPROVED_008_FaultStateReadOnly → PASS
FaultState has read privilege (View) and NO write privilege.
```
Section 9.3.10.5: "It is assumed that the fault will be cleared locally on the EVSE device." Remote fault clearance via Matter is structurally impossible.

### PROP_EVSE_031 — RandomizationDelayWindow Grid Demand → **DISPROVED**

RandomizationDelayWindow requires Manage privilege for writes and has max constraint of 86400. Verified:
```
SpecGap test: DISPROVED_031_RandomizationDelayWindowManageProtected → PASS
SpecGap test: DISPROVED_031_RandomizationDelayWindowMaxConstant → PASS
```
Market-specific grid requirements are enforced through regulatory certification, not the Matter protocol spec.

### PROP_EVSE_035 — RFID Authorization External Dependency → **DISPROVED**

RFID authorization is explicitly scoped out of the cluster (Section 9.3.4.4). An Operate-level attacker can already call EnableCharging directly without needing RFID events — RFID introduces zero additional attack surface.

---

## Test Inventory

### E2E Tests (TestEnergyEvseE2E.cpp) — 13 tests

| # | Test Name | Property | Type |
|---|---|---|---|
| 1 | PROP011_StartDiagnosticsFromDisabled | PROP_EVSE_011 | State transition |
| 2 | PROP011_StartDiagnosticsRejectedWhenCharging | PROP_EVSE_011 | Guard validation |
| 3 | PROP011_EnableChargingBlockedDuringDiagnostics | PROP_EVSE_011 | DoS proof |
| 4 | PROP011_EnableDischargingBlockedDuringDiagnostics | PROP_EVSE_011 | V2X DoS proof |
| 5 | PROP011_RepeatedDiagnosticsDoSLoop | PROP_EVSE_011 | Infinite loop attack |
| 6 | PROP011_DisableCommandDuringDiagnostics | PROP_EVSE_011 | Escape analysis |
| 7 | PROP011_DiagnosticsAndChargingUseSamePrivilege | PROP_EVSE_011 | Privilege asymmetry |
| 8 | PROP036_ChargingEnabledUntilAcceptsEpochValue | PROP_EVSE_036 | Epoch acceptance |
| 9 | PROP036_NullChargingEnabledUntilMeansIndefinite | PROP_EVSE_036 | Null = indefinite |
| 10 | PROP036_DischargingEnabledUntilAcceptsEpochValue | PROP_EVSE_036 | V2X epoch |
| 11 | PROP036_PastEpochValueAccepted | PROP_EVSE_036 | Past time attack |
| 12 | PROP036_ZeroEpochValueAccepted | PROP_EVSE_036 | Zero epoch attack |
| 13 | PROP036_LargeEpochValueAccepted | PROP_EVSE_036 | Far-future epoch |

### SpecGap Tests (TestEnergyEvseSpecGap.cpp) — 10 tests

| # | Test Name | Property | Type |
|---|---|---|---|
| 1 | PROP011_StartDiagnosticsMetadataTimedAndOperate | PROP_EVSE_011 | Metadata check |
| 2 | PROP011_EnableChargingMetadataTimedAndOperate | PROP_EVSE_011 | Metadata check |
| 3 | PROP011_NoCancelDiagnosticsCommand | PROP_EVSE_011 | Missing command |
| 4 | PROP011_NoDiagnosticsDurationAttribute | PROP_EVSE_011 | Missing attribute |
| 5 | PROP011_AllCommandsSameOperatePrivilege | PROP_EVSE_011 | Privilege analysis |
| 6 | DISPROVED_001_AllCommandsRequireTimedInvoke | PROP_EVSE_001 | Defense verification |
| 7 | PROP036_EpochAttributesExistWithNoTimeQuality | PROP_EVSE_036 | Missing attribute |
| 8 | DISPROVED_008_FaultStateReadOnly | PROP_EVSE_008 | Defense verification |
| 9 | DISPROVED_031_RandomizationDelayWindowManageProtected | PROP_EVSE_031 | Defense verification |
| 10 | DISPROVED_031_RandomizationDelayWindowMaxConstant | PROP_EVSE_031 | Constant check |

---

## Recommended Specification Changes

### PROP_EVSE_011 (HIGH priority):
1. Separate StartDiagnostics privilege to **Manage (M)**, not Operate (O)
2. Add `MaximumDiagnosticsDuration` attribute (uint32, seconds, mandatory max e.g. 60s)
3. Add `CancelDiagnostics` command (Manage privilege) to abort diagnostics
4. Add auto-completion at `t + MaximumDiagnosticsDuration`

### PROP_EVSE_036 (MEDIUM priority):
1. Add `TimeSourceQuality` attribute to indicate time source reliability
2. Define minimum time quality for epoch-based enforcement
3. Add clock-sync failure fallback: continue with locally maintained elapsed timer
4. Require time source integrity verification when using Time Synchronization cluster

---

## Files Modified

| File | Change |
|---|---|
| `src/app/clusters/energy-evse-server/tests/BUILD.gn` | New: test build configuration |
| `src/app/clusters/energy-evse-server/tests/EnergyEvseTestStubs.cpp` | New: link stubs |
| `src/app/clusters/energy-evse-server/tests/TestEnergyEvseE2E.cpp` | New: 13 E2E attack tests |
| `src/app/clusters/energy-evse-server/tests/TestEnergyEvseSpecGap.cpp` | New: 10 metadata tests |
| `src/BUILD.gn` | Added energy-evse-server/tests to test group |
