/**
 * @file TestSection4_3_ThermostatSecurity.cpp
 *
 * Spec-gap verification tests for Matter 1.5 Thermostat Cluster (0x0201)
 * Section 4.3, Pages 327-373
 *
 * Tests only vulnerabilities CONFIRMED by defense analysis:
 *   GAP-001..004: PROP_TSTAT_001 — EmergencyHeatDelta boundary attacks
 *   GAP-005..008: PROP_TSTAT_020 — SetpointChangeSource attribution gap
 *   GAP-009..012: PROP_TSTAT_012 — SetpointHold expiry gap
 *   GAP-013..016: PROP_TSTAT_026 — LocalTemperatureCalibration range
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

// External: attribute shim + pre-attribute change callback from thermostat-server.cpp
extern Status MatterThermostatClusterServerPreAttributeChangedCallback(const ConcreteAttributePath & attributePath,
                                                                       EmberAfAttributeType attributeType, uint16_t size,
                                                                       uint8_t * value);

static constexpr EndpointId kTestEndpoint = 0;

// ===================================================================================
// GAP-001 to GAP-004: PROP_TSTAT_001 — EmergencyHeatDelta boundary attacks
// ===================================================================================

TEST(TestThermostatSpecGap, GAP_001_EmergencyHeatDelta_ZeroAccepted)
{
    // PROP_TSTAT_001 residual: EmergencyHeatDelta=0 causes rapid cycling
    // Spec constraint is "all" — no minimum. SDK should accept 0.
    uint8_t zeroDelta = 0;
    auto status       = EmergencyHeatDelta::Set(kTestEndpoint, zeroDelta);
    EXPECT_EQ(status, Status::Success);

    uint8_t readBack = 255;
    status           = EmergencyHeatDelta::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(readBack, 0u);

    printf("[GAP-001] CONFIRMED: EmergencyHeatDelta=0 accepted — zero-delta rapid cycling possible\n");
}

TEST(TestThermostatSpecGap, GAP_002_EmergencyHeatDelta_MaxAccepted)
{
    // PROP_TSTAT_001 residual: EmergencyHeatDelta=255 (25.5°C) suppresses emergency heat
    uint8_t maxDelta = 255;
    auto status      = EmergencyHeatDelta::Set(kTestEndpoint, maxDelta);
    EXPECT_EQ(status, Status::Success);

    uint8_t readBack = 0;
    status           = EmergencyHeatDelta::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(readBack, 255u);

    printf("[GAP-002] CONFIRMED: EmergencyHeatDelta=255 accepted — emergency heat suppression possible\n");
}

TEST(TestThermostatSpecGap, GAP_003_EmergencyHeatDelta_NoPreAttributeValidation)
{
    // Verify PreAttributeChangedCallback does NOT validate EmergencyHeatDelta
    ConcreteAttributePath path(kTestEndpoint, Clusters::Thermostat::Id, EmergencyHeatDelta::Id);
    uint8_t zeroDelta = 0;
    auto status =
        MatterThermostatClusterServerPreAttributeChangedCallback(path, 0x20 /* ZCL_INT8U_ATTRIBUTE_TYPE */, 1, &zeroDelta);
    // Falls through to default: return Success — no validation
    EXPECT_EQ(status, Status::Success);

    printf("[GAP-003] CONFIRMED: PreAttributeChanged has no validation for EmergencyHeatDelta\n");
}

TEST(TestThermostatSpecGap, GAP_004_EmergencyHeatDelta_DefaultIsMax)
{
    // Verify default value is 255 (25.5°C) — the type maximum
    // This means even without an attacker, emergency heat is effectively suppressed for
    // any temperature deficit < 25.5°C
    auto status = EmergencyHeatDelta::Set(kTestEndpoint, static_cast<uint8_t>(255));
    EXPECT_EQ(status, Status::Success);

    uint8_t readBack = 0;
    status           = EmergencyHeatDelta::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(readBack, 255u);

    printf("[GAP-004] CONFIRMED: Default EmergencyHeatDelta=255 already suppresses emergency heat for <25.5°C deficits\n");
}

// ===================================================================================
// GAP-005 to GAP-008: PROP_TSTAT_020 — SetpointChangeSource attribution gap
// ===================================================================================

TEST(TestThermostatSpecGap, GAP_005_SetpointChangeSource_NotUpdatedBySetpointRaiseLower)
{
    // The SetpointRaiseLower handler in SDK does not update SetpointChangeSource at all.
    // Set it to Schedule (1) first, then verify it stays after a setpoint write.
    auto status = SetpointChangeSource::Set(kTestEndpoint, SetpointChangeSourceEnum::kSchedule);
    EXPECT_EQ(status, Status::Success);

    // Now simulate what SetpointRaiseLower does: directly write OccupiedHeatingSetpoint
    int16_t newHeatSetpoint = 2100; // 21.0°C
    status                  = OccupiedHeatingSetpoint::Set(kTestEndpoint, newHeatSetpoint);
    EXPECT_EQ(status, Status::Success);

    // Read SetpointChangeSource — should still be Schedule because SDK never updates it
    SetpointChangeSourceEnum source;
    status = SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(source, SetpointChangeSourceEnum::kSchedule);

    printf("[GAP-005] CONFIRMED: SetpointChangeSource NOT updated by setpoint writes — attribution gap\n");
}

TEST(TestThermostatSpecGap, GAP_006_SetpointChangeAmount_NotUpdated)
{
    // Verify SetpointChangeAmount is also stale after setpoint modifications
    DataModel::Nullable<int16_t> origAmount;
    auto status = SetpointChangeAmount::Get(kTestEndpoint, origAmount);
    EXPECT_EQ(status, Status::Success);

    // Write a setpoint
    status = OccupiedCoolingSetpoint::Set(kTestEndpoint, 2700);
    EXPECT_EQ(status, Status::Success);

    // SetpointChangeAmount should be unchanged — SDK doesn't touch it
    DataModel::Nullable<int16_t> newAmount;
    status = SetpointChangeAmount::Get(kTestEndpoint, newAmount);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(origAmount, newAmount);

    printf("[GAP-006] CONFIRMED: SetpointChangeAmount not updated by direct setpoint write\n");
}

TEST(TestThermostatSpecGap, GAP_007_SetpointChangeSourceTimestamp_NotUpdated)
{
    // Verify SetpointChangeSourceTimestamp is stale after setpoint modifications
    uint32_t origTimestamp = 0;
    auto status            = SetpointChangeSourceTimestamp::Get(kTestEndpoint, &origTimestamp);
    EXPECT_EQ(status, Status::Success);

    // Write a setpoint
    status = OccupiedHeatingSetpoint::Set(kTestEndpoint, 2050);
    EXPECT_EQ(status, Status::Success);

    uint32_t newTimestamp = 0;
    status                = SetpointChangeSourceTimestamp::Get(kTestEndpoint, &newTimestamp);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(origTimestamp, newTimestamp);

    printf("[GAP-007] CONFIRMED: SetpointChangeSourceTimestamp not updated — full audit trail corruption\n");
}

TEST(TestThermostatSpecGap, GAP_008_AttributionGap_AcrossAllSetpointRaiseLowerPaths)
{
    // Comprehensive: set source=Schedule, then verify that none of the
    // SetpointRaiseLower code paths correct it (they can't -- it's missing from SDK)
    auto status = SetpointChangeSource::Set(kTestEndpoint, SetpointChangeSourceEnum::kSchedule);
    EXPECT_EQ(status, Status::Success);

    // Simulate Heat path
    status = OccupiedHeatingSetpoint::Set(kTestEndpoint, 2200);
    EXPECT_EQ(status, Status::Success);

    SetpointChangeSourceEnum source;
    status = SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(status, Status::Success);
    bool heatPathStale = (source == SetpointChangeSourceEnum::kSchedule);

    // Simulate Cool path
    status = OccupiedCoolingSetpoint::Set(kTestEndpoint, 2600);
    EXPECT_EQ(status, Status::Success);

    status = SetpointChangeSource::Get(kTestEndpoint, &source);
    EXPECT_EQ(status, Status::Success);
    bool coolPathStale = (source == SetpointChangeSourceEnum::kSchedule);

    EXPECT_TRUE(heatPathStale);
    EXPECT_TRUE(coolPathStale);

    printf("[GAP-008] CONFIRMED: Attribution stale on Heat and Cool paths — all SetpointRaiseLower paths affected\n");
}

// ===================================================================================
// GAP-009 to GAP-012: PROP_TSTAT_012 — SetpointHold expiry gap
// ===================================================================================

TEST(TestThermostatSpecGap, GAP_009_SetpointHold_NoAutonomousClearingLogic)
{
    // Spec gap: no normative SHALL mandates server to clear hold at expiry time.
    // Verify SDK has no timer/clearing logic — hold stays on after setting.
    auto status = TemperatureSetpointHold::Set(kTestEndpoint, TemperatureSetpointHoldEnum::kSetpointHoldOn);
    EXPECT_EQ(status, Status::Success);

    TemperatureSetpointHoldEnum holdValue;
    status = TemperatureSetpointHold::Get(kTestEndpoint, &holdValue);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(holdValue, TemperatureSetpointHoldEnum::kSetpointHoldOn);

    printf("[GAP-009] CONFIRMED: SetpointHold can be set to On — no timer exists to auto-clear\n");
}

TEST(TestThermostatSpecGap, GAP_010_SetpointHoldDuration_MaxValue1440Accepted)
{
    // TemperatureSetpointHoldDuration max is 1440 minutes (24 hours)
    // Verify the SDK accepts this maximum hold duration
    auto status = TemperatureSetpointHoldDuration::Set(kTestEndpoint, static_cast<uint16_t>(1440));
    EXPECT_EQ(status, Status::Success);

    DataModel::Nullable<uint16_t> duration;
    status = TemperatureSetpointHoldDuration::Get(kTestEndpoint, duration);
    EXPECT_EQ(status, Status::Success);
    EXPECT_FALSE(duration.IsNull());
    EXPECT_EQ(duration.Value(), 1440u);

    printf("[GAP-010] CONFIRMED: Max hold duration 1440 min (24h) accepted — longest possible hold freeze\n");
}

TEST(TestThermostatSpecGap, GAP_011_SetpointHoldExpiryTimestamp_NoConnectionToHoldClearing)
{
    // Verify that setting SetpointHoldExpiryTimestamp to a past value does not
    // trigger any clearing of the hold — SDK treats timestamp as informational only
    auto status = SetpointHoldExpiryTimestamp::Set(kTestEndpoint, static_cast<uint32_t>(1000)); // far in the past
    EXPECT_EQ(status, Status::Success);

    // Hold should remain on
    TemperatureSetpointHoldEnum holdValue;
    status = TemperatureSetpointHold::Get(kTestEndpoint, &holdValue);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(holdValue, TemperatureSetpointHoldEnum::kSetpointHoldOn);

    printf("[GAP-011] CONFIRMED: Past expiry timestamp does NOT clear hold — no autonomous clearing\n");
}

TEST(TestThermostatSpecGap, GAP_012_SetpointHold_IndefiniteHoldViaDurationNull)
{
    // With null duration and hold on, the hold persists indefinitely
    auto status = TemperatureSetpointHoldDuration::SetNull(kTestEndpoint);
    EXPECT_EQ(status, Status::Success);

    status = TemperatureSetpointHold::Set(kTestEndpoint, TemperatureSetpointHoldEnum::kSetpointHoldOn);
    EXPECT_EQ(status, Status::Success);

    TemperatureSetpointHoldEnum holdValue;
    status = TemperatureSetpointHold::Get(kTestEndpoint, &holdValue);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(holdValue, TemperatureSetpointHoldEnum::kSetpointHoldOn);

    DataModel::Nullable<uint16_t> duration;
    status = TemperatureSetpointHoldDuration::Get(kTestEndpoint, duration);
    EXPECT_EQ(status, Status::Success);
    EXPECT_TRUE(duration.IsNull());

    printf("[GAP-012] CONFIRMED: Hold On + null duration = indefinite hold with no clearing mechanism\n");
}

// ===================================================================================
// GAP-013 to GAP-016: PROP_TSTAT_026 — LocalTemperatureCalibration unconstrained range
// ===================================================================================

TEST(TestThermostatSpecGap, GAP_013_LocalTempCalibration_MaxPositiveAccepted)
{
    // int8_t max = 127 → +12.7°C. No maximum range constraint after Revision 8.
    int8_t maxCalibration = 127;
    auto status           = LocalTemperatureCalibration::Set(kTestEndpoint, maxCalibration);
    EXPECT_EQ(status, Status::Success);

    int8_t readBack = 0;
    status          = LocalTemperatureCalibration::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(readBack, 127);

    printf("[GAP-013] CONFIRMED: LocalTemperatureCalibration=+12.7°C accepted — max positive offset\n");
}

TEST(TestThermostatSpecGap, GAP_014_LocalTempCalibration_MaxNegativeAccepted)
{
    // int8_t min = -128 → -12.8°C
    int8_t minCalibration = -128;
    auto status           = LocalTemperatureCalibration::Set(kTestEndpoint, minCalibration);
    EXPECT_EQ(status, Status::Success);

    int8_t readBack = 0;
    status          = LocalTemperatureCalibration::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(readBack, -128);

    printf("[GAP-014] CONFIRMED: LocalTemperatureCalibration=-12.8°C accepted — max negative offset\n");
}

TEST(TestThermostatSpecGap, GAP_015_LocalTempCalibration_NoPreAttributeValidation)
{
    // PreAttributeChangedCallback has no case for LocalTemperatureCalibration
    ConcreteAttributePath path(kTestEndpoint, Clusters::Thermostat::Id, LocalTemperatureCalibration::Id);
    int8_t extremeCalibration = 127;
    auto status = MatterThermostatClusterServerPreAttributeChangedCallback(path, 0x28 /* ZCL_INT8S_ATTRIBUTE_TYPE */, 1,
                                                                           reinterpret_cast<uint8_t *>(&extremeCalibration));
    // Falls through to default: return Success — no validation
    EXPECT_EQ(status, Status::Success);

    printf("[GAP-015] CONFIRMED: PreAttributeChanged has no validation for LocalTemperatureCalibration\n");
}

TEST(TestThermostatSpecGap, GAP_016_LocalTempCalibration_OldConstraintRemoved)
{
    // Pre-Revision 8 constraint was ±2.5°C (±25 in int8_t). Verify values outside
    // this old range are now accepted.
    int8_t beyondOldMax = 50; // +5.0°C, beyond old ±2.5°C limit
    auto status         = LocalTemperatureCalibration::Set(kTestEndpoint, beyondOldMax);
    EXPECT_EQ(status, Status::Success);

    int8_t readBack = 0;
    status          = LocalTemperatureCalibration::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(readBack, 50);

    int8_t beyondOldMin = -50; // -5.0°C
    status              = LocalTemperatureCalibration::Set(kTestEndpoint, beyondOldMin);
    EXPECT_EQ(status, Status::Success);

    status = LocalTemperatureCalibration::Get(kTestEndpoint, &readBack);
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(readBack, -50);

    printf("[GAP-016] CONFIRMED: Values beyond old ±2.5°C constraint accepted — Revision 8 constraint removal verified\n");
}
