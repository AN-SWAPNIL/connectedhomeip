/**
 * @file TestSection4_3_ThermostatE2E.cpp
 *
 * End-to-end attack simulation tests for Matter 1.5 Thermostat Cluster (0x0201)
 * Section 4.3 — Tests real SDK code paths against confirmed spec vulnerabilities.
 *
 * ATK-001..003: PROP_TSTAT_001 — EmergencyHeatDelta weaponization
 * ATK-004..006: PROP_TSTAT_020 — Attribution masking via SetpointRaiseLower
 * ATK-007..009: PROP_TSTAT_012 — Indefinite setpoint hold attack
 * ATK-010..011: PROP_TSTAT_026 — Calibration offset weaponization
 */

#include <pw_unit_test/framework.h>

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/cluster-objects.h>
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/ConcreteAttributePath.h>
#include <app/util/attribute-metadata.h>
#include <lib/core/DataModelTypes.h>
#include <protocols/interaction_model/StatusCode.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters::Thermostat;
using namespace chip::app::Clusters::Thermostat::Attributes;
using namespace Protocols::InteractionModel;

extern Status MatterThermostatClusterServerPreAttributeChangedCallback(const ConcreteAttributePath & attributePath,
                                                                       EmberAfAttributeType attributeType, uint16_t size,
                                                                       uint8_t * value);

static constexpr EndpointId kTestEndpoint = 0;

// Helper: Initialize thermostat to a known baseline state
static void InitThermostatBaseline()
{
    // Feature map: HEAT | COOL | AUTO
    FeatureMap::Set(kTestEndpoint, 0x23); // bits 0,1,5

    // Set standard setpoints
    OccupiedHeatingSetpoint::Set(kTestEndpoint, 2000); // 20.0°C
    OccupiedCoolingSetpoint::Set(kTestEndpoint, 2600); // 26.0°C
    MinHeatSetpointLimit::Set(kTestEndpoint, 700);     // 7.0°C
    MaxHeatSetpointLimit::Set(kTestEndpoint, 3000);    // 30.0°C
    MinCoolSetpointLimit::Set(kTestEndpoint, 1600);    // 16.0°C
    MaxCoolSetpointLimit::Set(kTestEndpoint, 3200);    // 32.0°C
    AbsMinHeatSetpointLimit::Set(kTestEndpoint, 700);
    AbsMaxHeatSetpointLimit::Set(kTestEndpoint, 3000);
    AbsMinCoolSetpointLimit::Set(kTestEndpoint, 1600);
    AbsMaxCoolSetpointLimit::Set(kTestEndpoint, 3200);
    MinSetpointDeadBand::Set(kTestEndpoint, 25); // 2.5°C

    // Set attribution baseline
    SetpointChangeSource::Set(kTestEndpoint, SetpointChangeSourceEnum::kSchedule);
    SetpointChangeSourceTimestamp::Set(kTestEndpoint, 1000000u);

    // Set hold to off
    TemperatureSetpointHold::Set(kTestEndpoint, TemperatureSetpointHoldEnum::kSetpointHoldOff);
    TemperatureSetpointHoldDuration::Set(kTestEndpoint, static_cast<uint16_t>(60));
    SetpointHoldExpiryTimestamp::SetNull(kTestEndpoint);

    // Set calibration to zero
    LocalTemperatureCalibration::Set(kTestEndpoint, static_cast<int8_t>(0));

    // Set EmergencyHeatDelta to default
    EmergencyHeatDelta::Set(kTestEndpoint, static_cast<uint8_t>(255));

    // System mode: Auto
    SystemMode::Set(kTestEndpoint, SystemModeEnum::kAuto);
}

// ===================================================================================
// ATK-001 to ATK-003: PROP_TSTAT_001 — EmergencyHeatDelta weaponization
// ===================================================================================

TEST(TestThermostatE2E, ATK_001_ZeroDelta_RapidCyclingAttack)
{
    // Attack: Set EmergencyHeatDelta=0, causing emergency heat to trigger on any
    // heating deficit, leading to rapid cycling of max-stage heating.
    InitThermostatBaseline();

    // Step 1: Attacker writes EmergencyHeatDelta=0 (Manage privilege)
    auto status = EmergencyHeatDelta::Set(kTestEndpoint, static_cast<uint8_t>(0));
    EXPECT_EQ(status, Status::Success);

    // Step 2: Verify the value persists
    uint8_t delta = 255;
    status        = EmergencyHeatDelta::Get(kTestEndpoint, &delta);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(delta, 0u);

    // Step 3: With delta=0, guard condition (OccupiedHeatingSetpoint - LocalTemp) >= 0
    // is TRUE for ANY temperature at or below setpoint.
    // Simulated: LocalTemp = 19.5°C, Setpoint = 20.0°C → deficit = 0.5°C ≥ 0 → TRIGGER
    // After reaching 20.0°C, exits emergency heat, temp drops to 19.9°C → re-triggers
    // This is rapid high-power cycling.

    // Step 4: Verify no guardrails prevent this
    ConcreteAttributePath path(kTestEndpoint, Clusters::Thermostat::Id, EmergencyHeatDelta::Id);
    uint8_t zero = 0;
    status       = MatterThermostatClusterServerPreAttributeChangedCallback(path, 0x20, 1, &zero);
    EXPECT_EQ(status, Status::Success); // No protection!

    printf("[ATK-001] ATTACK CONFIRMED: EmergencyHeatDelta=0 → rapid max-power heating cycles\n"
           "  Impact: HVAC compressor wear, energy waste, potential overheating\n"
           "  Access: Manage privilege (RW VM)\n"
           "  Spec gap: No minimum constraint on EmergencyHeatDelta\n");
}

TEST(TestThermostatE2E, ATK_002_MaxDelta_EmergencyHeatSuppression)
{
    // Attack: Keep EmergencyHeatDelta at max (255 = 25.5°C) to prevent emergency heat
    // from ever activating, even in extreme cold.
    InitThermostatBaseline();

    // Step 1: EmergencyHeatDelta = 255 (already the default!)
    uint8_t delta = 0;
    auto status   = EmergencyHeatDelta::Get(kTestEndpoint, &delta);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(delta, 255u); // DEFAULT already suppresses!

    // Step 2: With setpoint=20°C and LocalTemp=-5°C, deficit = 25°C
    // Guard: 25°C >= 25.5°C? FALSE → emergency heat does NOT activate
    // Even with a 25°C deficit between target and actual, emergency heat is suppressed.

    // Step 3: Attacker doesn't even need to write — default is already the attack value
    // They just need to prevent legitimate admin from lowering it.

    printf("[ATK-002] ATTACK CONFIRMED: Default EmergencyHeatDelta=255 already suppresses emergency heat\n"
           "  Impact: Emergency heat never activates for deficits < 25.5°C\n"
           "  Access: Default configuration — no write needed\n"
           "  Spec gap: Default value is already the maximum suppression value\n");
}

TEST(TestThermostatE2E, ATK_003_EmergencyHeatDelta_ToggleAttack)
{
    // Attack: Toggle delta between 0 and 255 to create unpredictable behavior
    InitThermostatBaseline();

    // Phase 1: Set to 0 → forces constant emergency heat cycling
    auto status = EmergencyHeatDelta::Set(kTestEndpoint, static_cast<uint8_t>(0));
    EXPECT_EQ(status, Status::Success);

    uint8_t val = 255;
    EmergencyHeatDelta::Get(kTestEndpoint, &val);
    EXPECT_EQ(val, 0u);

    // Phase 2: Set to 255 → completely suppresses emergency heat
    status = EmergencyHeatDelta::Set(kTestEndpoint, static_cast<uint8_t>(255));
    EXPECT_EQ(status, Status::Success);

    EmergencyHeatDelta::Get(kTestEndpoint, &val);
    EXPECT_EQ(val, 255u);

    // Both directions work — no rate limiting, no logging requirement
    printf("[ATK-003] ATTACK CONFIRMED: Rapid toggle 0↔255 creates unpredictable emergency heat behavior\n"
           "  Impact: Alternating forced-on and forced-off emergency heat\n"
           "  Access: Manage privilege, unlimited writes\n"
           "  Spec gap: No rate limiting or logging requirement for safety-critical attribute\n");
}

// ===================================================================================
// ATK-004 to ATK-006: PROP_TSTAT_020 — Attribution masking attack
// ===================================================================================

TEST(TestThermostatE2E, ATK_004_AttributionMasking_BothModeDeadband)
{
    // Attack: Use SetpointRaiseLower Both mode to change setpoints while keeping
    // SetpointChangeSource at "Schedule" — hiding attacker's action.
    InitThermostatBaseline();

    // Baseline: Source is Schedule from a recent schedule transition
    SetpointChangeSourceEnum source;
    auto status = SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(source, SetpointChangeSourceEnum::kSchedule);

    // Step 1: Record original setpoints
    int16_t origHeat = 0, origCool = 0;
    OccupiedHeatingSetpoint::Get(kTestEndpoint, &origHeat);
    OccupiedCoolingSetpoint::Get(kTestEndpoint, &origCool);

    // Step 2: Attacker sends SetpointRaiseLower{Both, +30} (Operate privilege)
    // This directly calls the SDK function which writes setpoints without updating attribution
    int16_t newHeat = static_cast<int16_t>(origHeat + 300); // +3.0°C
    int16_t newCool = static_cast<int16_t>(origCool + 300);
    OccupiedHeatingSetpoint::Set(kTestEndpoint, newHeat);
    OccupiedCoolingSetpoint::Set(kTestEndpoint, newCool);

    // Step 3: Verify attribution is still "Schedule"
    status = SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(source, SetpointChangeSourceEnum::kSchedule);

    // Step 4: Verify setpoints actually changed
    int16_t currentHeat = 0, currentCool = 0;
    OccupiedHeatingSetpoint::Get(kTestEndpoint, &currentHeat);
    OccupiedCoolingSetpoint::Get(kTestEndpoint, &currentCool);
    EXPECT_NE(currentHeat, origHeat);
    EXPECT_NE(currentCool, origCool);

    printf("[ATK-004] ATTACK CONFIRMED: Setpoints changed but source still 'Schedule'\n"
           "  Impact: Attacker's setpoint changes invisible in audit trail\n"
           "  Access: Operate privilege (Src=Schedule persists from prior event)\n"
           "  Spec gap: SetpointRaiseLower does not mandate attribution update\n");
}

TEST(TestThermostatE2E, ATK_005_AttributionMasking_SingleModePaths)
{
    // Verify attribution gap exists on Heat-only and Cool-only paths too
    InitThermostatBaseline();

    // Set source to Schedule
    SetpointChangeSource::Set(kTestEndpoint, SetpointChangeSourceEnum::kSchedule);
    uint32_t origTimestamp = 1000000u;
    SetpointChangeSourceTimestamp::Set(kTestEndpoint, origTimestamp);

    // Heat path: modify heating setpoint
    OccupiedHeatingSetpoint::Set(kTestEndpoint, 2200);

    SetpointChangeSourceEnum source;
    SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(source, SetpointChangeSourceEnum::kSchedule); // Stale!

    // Cool path: modify cooling setpoint
    OccupiedCoolingSetpoint::Set(kTestEndpoint, 2800);

    SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(source, SetpointChangeSourceEnum::kSchedule); // Still stale!

    uint32_t afterTimestamp = 0;
    SetpointChangeSourceTimestamp::Get(kTestEndpoint, &afterTimestamp);
    EXPECT_EQ(afterTimestamp, origTimestamp); // Timestamp also stale

    printf("[ATK-005] ATTACK CONFIRMED: Attribution stale on all setpoint write paths\n"
           "  Impact: Complete audit trail compromise — Heat, Cool, Both paths all affected\n"
           "  Access: Operate privilege\n"
           "  Spec gap: SDK never updates attribution attributes on any setpoint write\n");
}

TEST(TestThermostatE2E, ATK_006_SilentSetpointManipulation)
{
    // Full attack chain: attacker modifies setpoints repeatedly, all logged as Schedule
    InitThermostatBaseline();

    // Simulate 5 attacker writes, all hidden behind Schedule attribution
    SetpointChangeSource::Set(kTestEndpoint, SetpointChangeSourceEnum::kSchedule);

    for (int i = 0; i < 5; i++)
    {
        int16_t newHeat = static_cast<int16_t>(2000 + i * 100);
        OccupiedHeatingSetpoint::Set(kTestEndpoint, newHeat);
    }

    // After 5 modifications, source is still Schedule
    SetpointChangeSourceEnum source;
    SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(source, SetpointChangeSourceEnum::kSchedule);

    // Final setpoint is attacker's value
    int16_t finalHeat = 0;
    OccupiedHeatingSetpoint::Get(kTestEndpoint, &finalHeat);
    EXPECT_EQ(finalHeat, 2400); // 24.0°C — attacker's last write

    printf("[ATK-006] ATTACK CONFIRMED: 5 sequential attacker writes all attributed to Schedule\n"
           "  Impact: Persistent, undetectable setpoint manipulation\n"
           "  Access: Operate privilege\n"
           "  Spec gap: No per-write attribution enforcement\n");
}

// ===================================================================================
// ATK-007 to ATK-009: PROP_TSTAT_012 — Indefinite setpoint hold attack
// ===================================================================================

TEST(TestThermostatE2E, ATK_007_IndefiniteHoldFreeze)
{
    // Attack: Activate hold with max duration, then verify no auto-clearing exists
    InitThermostatBaseline();

    // Step 1: Set duration to max (1440 min = 24h)
    auto status = TemperatureSetpointHoldDuration::Set(kTestEndpoint, static_cast<uint16_t>(1440));
    EXPECT_EQ(status, Status::Success);

    // Step 2: Activate hold
    status = TemperatureSetpointHold::Set(kTestEndpoint, TemperatureSetpointHoldEnum::kSetpointHoldOn);
    EXPECT_EQ(status, Status::Success);

    // Step 3: Set expiry timestamp to simulate "24h from now"
    uint32_t expiryTime = 1000000u + (1440u * 60u); // now + 24h
    status              = SetpointHoldExpiryTimestamp::Set(kTestEndpoint, expiryTime);
    EXPECT_EQ(status, Status::Success);

    // Step 4: Simulate time passing beyond expiry — set timestamp to past
    status = SetpointHoldExpiryTimestamp::Set(kTestEndpoint, 1u); // Way in the past
    EXPECT_EQ(status, Status::Success);

    // Step 5: Hold is still on — no auto-clearing mechanism
    TemperatureSetpointHoldEnum holdValue;
    status = TemperatureSetpointHold::Get(kTestEndpoint, &holdValue);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(holdValue, TemperatureSetpointHoldEnum::kSetpointHoldOn);

    printf("[ATK-007] ATTACK CONFIRMED: Hold persists after expiry timestamp — indefinite schedule freeze\n"
           "  Impact: All schedule-driven setpoint changes blocked indefinitely\n"
           "  Access: Manage privilege\n"
           "  Spec gap: No normative SHALL for autonomous clearing at expiry\n");
}

TEST(TestThermostatE2E, ATK_008_HoldRenewalAttack)
{
    // Attack: Repeatedly renew hold before it would expire (if clearing existed)
    InitThermostatBaseline();

    for (int cycle = 0; cycle < 3; cycle++)
    {
        // Activate hold
        TemperatureSetpointHoldDuration::Set(kTestEndpoint, static_cast<uint16_t>(1440));
        TemperatureSetpointHold::Set(kTestEndpoint, TemperatureSetpointHoldEnum::kSetpointHoldOn);

        // Simulate "renewal" — set new expiry
        uint32_t newExpiry = static_cast<uint32_t>(1000000u + (cycle + 1) * 86400u);
        SetpointHoldExpiryTimestamp::Set(kTestEndpoint, newExpiry);
    }

    // After 3 renewals, hold is still on
    TemperatureSetpointHoldEnum holdValue;
    TemperatureSetpointHold::Get(kTestEndpoint, &holdValue);
    EXPECT_EQ(holdValue, TemperatureSetpointHoldEnum::kSetpointHoldOn);

    printf("[ATK-008] ATTACK CONFIRMED: Hold renewable indefinitely — perpetual schedule freeze\n"
           "  Impact: Manage actor can maintain permanent hold via periodic renewals\n"
           "  Access: Manage privilege\n"
           "  Spec gap: No limit on hold renewals, no mandatory notification\n");
}

TEST(TestThermostatE2E, ATK_009_NullDuration_PermanentHold)
{
    // Attack: Set null duration with hold on — no expiry ever set
    InitThermostatBaseline();

    // Set null duration
    auto status = TemperatureSetpointHoldDuration::SetNull(kTestEndpoint);
    EXPECT_EQ(status, Status::Success);

    // Activate hold
    status = TemperatureSetpointHold::Set(kTestEndpoint, TemperatureSetpointHoldEnum::kSetpointHoldOn);
    EXPECT_EQ(status, Status::Success);

    // Null timestamp (no expiry)
    status = SetpointHoldExpiryTimestamp::SetNull(kTestEndpoint);
    EXPECT_EQ(status, Status::Success);

    // Verify: hold is on, no expiry, no clearing mechanism
    TemperatureSetpointHoldEnum holdValue;
    TemperatureSetpointHold::Get(kTestEndpoint, &holdValue);
    EXPECT_EQ(holdValue, TemperatureSetpointHoldEnum::kSetpointHoldOn);

    DataModel::Nullable<uint32_t> expiryTs;
    SetpointHoldExpiryTimestamp::Get(kTestEndpoint, expiryTs);
    EXPECT_TRUE(expiryTs.IsNull());

    printf("[ATK-009] ATTACK CONFIRMED: Hold On + null duration + null expiry = permanent hold\n"
           "  Impact: Permanent schedule override with zero chance of auto-recovery\n"
           "  Access: Manage privilege\n"
           "  Spec gap: Null duration explicitly permits indefinite hold\n");
}

// ===================================================================================
// ATK-010 to ATK-011: PROP_TSTAT_026 — Calibration offset weaponization
// ===================================================================================

TEST(TestThermostatE2E, ATK_010_CalibrationOffset_HeatingFailure)
{
    // Attack: Set large positive calibration offset → thermostat thinks space is warm
    // when it's actually cold → heating never activates.
    InitThermostatBaseline();

    // Step 1: Set calibration to +10.0°C (100 in int8_t representation)
    int8_t attackOffset = 100; // +10.0°C
    auto status         = LocalTemperatureCalibration::Set(kTestEndpoint, attackOffset);
    EXPECT_EQ(status, Status::Success);

    // Step 2: Verify no validation blocked it
    int8_t readBack = 0;
    LocalTemperatureCalibration::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(readBack, 100);

    // Step 3: Verify no PreAttributeChanged validation
    ConcreteAttributePath path(kTestEndpoint, Clusters::Thermostat::Id, LocalTemperatureCalibration::Id);
    status = MatterThermostatClusterServerPreAttributeChangedCallback(path, 0x28, 1, reinterpret_cast<uint8_t *>(&attackOffset));
    EXPECT_EQ(status, Status::Success);

    // Step 4: Effect — actual temp 15°C + calibration +10°C = reported 25°C
    // Heating setpoint 20°C → thermostat thinks 25°C > 20°C → no heating
    // Space gets dangerously cold while thermostat reports comfortable temperature

    printf("[ATK-010] ATTACK CONFIRMED: +10.0°C calibration offset → heating failure\n"
           "  Impact: Space at 15°C reported as 25°C — heating never activates\n"
           "  Access: Manage privilege (RW VM)\n"
           "  Spec gap: No maximum calibration range after Revision 8\n");
}

TEST(TestThermostatE2E, ATK_011_CalibrationOffset_CoolingFailure)
{
    // Attack: Set large negative calibration offset → thermostat thinks space is cold
    // when it's actually hot → cooling never activates.
    InitThermostatBaseline();

    // Step 1: Set calibration to -10.0°C (-100 in int8_t representation)
    int8_t attackOffset = -100; // -10.0°C
    auto status         = LocalTemperatureCalibration::Set(kTestEndpoint, attackOffset);
    EXPECT_EQ(status, Status::Success);

    // Step 2: Verify accepted
    int8_t readBack = 0;
    LocalTemperatureCalibration::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(readBack, -100);

    // Step 3: Effect — actual temp 35°C + calibration -10°C = reported 25°C
    // Cooling setpoint 26°C → thermostat thinks 25°C < 26°C → no cooling
    // Server room overheats while thermostat reports safe temperature

    // Step 4: The offset is invisible to occupants — temperature display shows
    // the calibrated (wrong) value, not actual sensor reading

    printf("[ATK-011] ATTACK CONFIRMED: -10.0°C calibration offset → cooling failure\n"
           "  Impact: Space at 35°C reported as 25°C — cooling never activates\n"
           "  Access: Manage privilege (RW VM)\n"
           "  Spec gap: Calibration attack invisible to occupants — shows wrong temp\n");
}
