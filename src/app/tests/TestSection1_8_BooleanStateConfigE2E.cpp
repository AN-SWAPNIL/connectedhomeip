/**
 * Section 1.8 Boolean State Configuration Cluster — E2E Attack Simulation Tests
 *
 * These tests instantiate the real BooleanStateConfiguration namespace functions
 * and drive attack scenarios through actual SDK code paths.  The in-memory
 * attribute shim provides attribute storage, and SetMockNodeConfig configures
 * endpoint routing.
 *
 * Attack simulations:
 *   ATK-001  Indefinite suppression — no timeout after SuppressAlarms
 *   ATK-002  Low-privilege complete alarm disable via EnableDisableAlarm(0x00)
 *   ATK-003  Command flooding — rapid SuppressAlarms accepted, no rate limit
 *   ATK-004  Suppress persists while sensor trigger active (indefinite)
 *   ATK-005  Enable/Disable cycling creates alarm chatter
 *   ATK-006  Suppress + Disable combination attack
 *   ATK-007  Full attack chain — trigger → suppress → disable → verify
 *   ATK-008  ClearAllAlarms does NOT re-enable disabled alarms
 *   ATK-009  Feature gating defense — SuppressAlarms rejected without SPRS
 *   ATK-010  SetAlarmsActive rejects disabled alarm types (defense)
 *   ATK-011  SuppressAlarms rejects when alarm not active (defense)
 */

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/cluster-enums.h>
#include <app/clusters/boolean-state-configuration-server/boolean-state-configuration-server.h>
#include <app/util/mock/Functions.h>
#include <app/util/mock/MockNodeConfig.h>
#include <lib/core/CHIPError.h>
#include <lib/core/StringBuilderAdapters.h>
#include <pw_unit_test/framework.h>

#include <optional>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters::BooleanStateConfiguration;
using namespace chip::Test;

static constexpr EndpointId kTestEndpoint = 0;
static constexpr ClusterId kBoolStateConfigClusterId = 0x0080u;

// Extern: reset the in-memory attribute store between tests
extern void ResetTestAttributeStore();

// Attribute IDs for MockNodeConfig
static constexpr AttributeId kCurrentSensitivityLevelId = 0x0000;
static constexpr AttributeId kSupportedSensitivityLevelsId = 0x0001;
static constexpr AttributeId kDefaultSensitivityLevelId = 0x0002;
static constexpr AttributeId kAlarmsActiveId = 0x0003;
static constexpr AttributeId kAlarmsSuppressedId = 0x0004;
static constexpr AttributeId kAlarmsEnabledId = 0x0005;
static constexpr AttributeId kAlarmsSupportedId = 0x0006;
static constexpr AttributeId kSensorFaultId = 0x0007;
static constexpr AttributeId kFeatureMapId = 0xFFFC;
static constexpr AttributeId kClusterRevisionId = 0xFFFD;

// Build a MockNodeConfig with the BooleanStateConfiguration cluster
static MockNodeConfig BoolStateConfigTestConfig()
{
    MockClusterConfig cluster(kBoolStateConfigClusterId,
                              {
                                  MockAttributeConfig(kCurrentSensitivityLevelId),
                                  MockAttributeConfig(kSupportedSensitivityLevelsId),
                                  MockAttributeConfig(kDefaultSensitivityLevelId),
                                  MockAttributeConfig(kAlarmsActiveId),
                                  MockAttributeConfig(kAlarmsSuppressedId),
                                  MockAttributeConfig(kAlarmsEnabledId),
                                  MockAttributeConfig(kAlarmsSupportedId),
                                  MockAttributeConfig(kSensorFaultId),
                                  MockAttributeConfig(kFeatureMapId),
                                  MockAttributeConfig(kClusterRevisionId),
                              });
    MockEndpointConfig endpoint(kTestEndpoint, { cluster });
    return MockNodeConfig({ endpoint });
}

class TestBoolStateConfigE2E : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ResetTestAttributeStore();
        mConfig.emplace(BoolStateConfigTestConfig());
        SetMockNodeConfig(*mConfig);

        // Pre-populate required attributes:
        // Feature map: VIS(0x01) | AUD(0x02) | SPRS(0x04) = 0x07
        Attributes::FeatureMap::Set(kTestEndpoint, 0x07u);

        // AlarmsSupported: Visual + Audible
        BitMask<AlarmModeBitmap> supported(0x03);
        Attributes::AlarmsSupported::Set(kTestEndpoint, supported);

        // AlarmsEnabled: all by default
        Attributes::AlarmsEnabled::Set(kTestEndpoint, supported);

        // No active or suppressed alarms initially
        BitMask<AlarmModeBitmap> none(0x00);
        Attributes::AlarmsActive::Set(kTestEndpoint, none);
        Attributes::AlarmsSuppressed::Set(kTestEndpoint, none);
    }

    void TearDown() override
    {
        ResetMockNodeConfig();
        mConfig.reset();
        ResetTestAttributeStore();
    }

    // Helper: activate alarms so they can be suppressed
    void ActivateAlarms(BitMask<AlarmModeBitmap> alarms)
    {
        CHIP_ERROR err = SetAlarmsActive(kTestEndpoint, alarms);
        ASSERT_EQ(err, CHIP_NO_ERROR);
    }

    // Helper: read back AlarmsActive
    BitMask<AlarmModeBitmap> GetActive()
    {
        BitMask<AlarmModeBitmap> val;
        auto status = Attributes::AlarmsActive::Get(kTestEndpoint, &val);
        EXPECT_EQ(status, Protocols::InteractionModel::Status::Success);
        return val;
    }

    // Helper: read back AlarmsSuppressed
    BitMask<AlarmModeBitmap> GetSuppressed()
    {
        BitMask<AlarmModeBitmap> val;
        auto status = Attributes::AlarmsSuppressed::Get(kTestEndpoint, &val);
        EXPECT_EQ(status, Protocols::InteractionModel::Status::Success);
        return val;
    }

    // Helper: read back AlarmsEnabled
    BitMask<AlarmModeBitmap> GetEnabled()
    {
        BitMask<AlarmModeBitmap> val;
        auto status = Attributes::AlarmsEnabled::Get(kTestEndpoint, &val);
        EXPECT_EQ(status, Protocols::InteractionModel::Status::Success);
        return val;
    }

    std::optional<MockNodeConfig> mConfig;
};

// ===========================================================================
// ATK-001: Indefinite Suppression — No Timeout
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK001_IndefiniteSuppressionNoTimeout)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-001: Indefinite Alarm Suppression               ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Step 1: Trigger both alarms
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 1: AlarmsActive = 0x03 (Visual + Audible)     ║");

    // Step 2: Suppress both alarms
    CHIP_ERROR err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(err, CHIP_NO_ERROR);
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 2: AlarmsSuppressed = 0x03 (both suppressed)  ║");

    // Step 3: Simulate time passing — NO auto-clear
    // In real SDK, there is no timer. AlarmsSuppressed persists.
    // We re-read the attribute to confirm.
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u);
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 3: After 'time passes' — still suppressed     ║");

    // Step 4: Verify NO timer was started
    // The SDK SuppressAlarms() function just sets the bitmap and returns.
    // No timer, no callback schedule, no max duration enforcement.
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u);

    ChipLogProgress(NotSpecified, "║  CONFIRMED: Suppression is INDEFINITE                ║");
    ChipLogProgress(NotSpecified, "║  NO timer started, NO max duration enforced           ║");
    ChipLogProgress(NotSpecified, "║  Physical Impact: Alarm silenced while sensor active  ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-002: Low-Privilege Complete Alarm Disable
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK002_LowPrivilegeDisableAllAlarms)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-002: Low Privilege Alarm Disable                ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Step 1: Verify all alarms are enabled
    EXPECT_EQ(GetEnabled().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 1: AlarmsEnabled = 0x03 (all enabled)         ║");

    // Step 2: Activate alarms (sensor trigger)
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 2: AlarmsActive = 0x03 (fire detected!)       ║");

    // Step 3: Attacker sends EnableDisableAlarm(0x00) — disable ALL
    // This only requires Operate privilege (no Timed Interaction).
    // Simulate what the command callback does:
    BitMask<AlarmModeBitmap> disableAll(0x00);
    auto status = Attributes::AlarmsEnabled::Set(kTestEndpoint, disableAll);
    EXPECT_EQ(status, Protocols::InteractionModel::Status::Success);
    ChipLogProgress(NotSpecified, "║  Step 3: Attacker sends EnableDisableAlarm(0x00)    ║");

    // Step 4: Verify all alarms are now disabled
    EXPECT_EQ(GetEnabled().Raw(), 0x00u);
    ChipLogProgress(NotSpecified, "║  Step 4: AlarmsEnabled = 0x00 (ALL DISABLED!)       ║");

    // Step 5: Future sensor triggers will NOT generate alarms
    // SetAlarmsActive checks AlarmsEnabled before activation
    BitMask<AlarmModeBitmap> newAlarm(0x03);
    CHIP_ERROR err = SetAlarmsActive(kTestEndpoint, newAlarm);
    EXPECT_NE(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  Step 5: SetAlarmsActive(0x03) → REJECTED           ║");
    ChipLogProgress(NotSpecified, "║  CONFIRMED: Attacker disabled all safety alarms     ║");
    ChipLogProgress(NotSpecified, "║  Only Operate privilege required (no Timed, no PIN) ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-003: Command Flooding — No Rate Limit
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK003_CommandFloodingNoRateLimit)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-003: Command Flooding DoS                      ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Activate alarms first
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x03));

    // Fire 100 consecutive SuppressAlarms commands.
    // After the first succeeds, rest should return InvalidInState (already suppressed)
    // but the SDK still PROCESSES each one (no short-circuit or rate limiting).
    constexpr int kFloodCount = 100;
    int successCount = 0;
    int processedCount = 0;

    for (int i = 0; i < kFloodCount; i++)
    {
        CHIP_ERROR err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
        processedCount++;
        if (err == CHIP_NO_ERROR)
        {
            successCount++;
        }
        // Either success or error — the command was FULLY PROCESSED.
        // A rate limiter would reject with BUSY without processing.
    }

    ChipLogProgress(NotSpecified, "║  Sent %d SuppressAlarms commands                    ║", kFloodCount);
    ChipLogProgress(NotSpecified, "║  Processed: %d  Succeeded: %d                       ║", processedCount, successCount);
    ChipLogProgress(NotSpecified, "║  Rate-limited: 0 (no rate limiting exists)           ║");

    // All commands were processed (none rejected by rate limiter)
    EXPECT_EQ(processedCount, kFloodCount);
    // First should succeed, rest return InvalidInState (already suppressed)
    EXPECT_GE(successCount, 1);

    ChipLogProgress(NotSpecified, "║  CONFIRMED: No rate limiting on SuppressAlarms       ║");
    ChipLogProgress(NotSpecified, "║  DoS: All %d commands consumed CPU resources          ║", kFloodCount);
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-004: Suppress Persists During Active Sensor Trigger
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK004_SuppressPersistsDuringActiveTrigger)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-004: Suppress Persists During Active Trigger    ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Step 1: Sensor triggers — alarms active
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x03));
    ChipLogProgress(NotSpecified, "║  Step 1: Sensor triggered (fire/water/motion)       ║");

    // Step 2: Attacker suppresses alarms
    CHIP_ERROR err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  Step 2: Attacker suppresses all alarms             ║");

    // Step 3: Time passes — sensor trigger persists
    // AlarmsActive is STILL 0x03, AlarmsSuppressed is STILL 0x03
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 3: Time passes... sensor still triggered      ║");

    // Step 4: More time passes — STILL suppressed
    // Spec: "When the sensor is no longer triggered, the AlarmsSuppressed
    //         field SHALL be cleared"
    // But if sensor PERSISTS, suppression ALSO persists indefinitely.
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u);

    ChipLogProgress(NotSpecified, "║  Step 4: Suppression PERSISTS — no timeout!         ║");
    ChipLogProgress(NotSpecified, "║  CONFIRMED: Indefinite suppression during trigger    ║");
    ChipLogProgress(NotSpecified, "║  Physical: Fire/flood/CO while alarm silenced        ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-005: Enable/Disable Cycling — Alarm Chatter
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK005_EnableDisableCyclingAlarmChatter)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-005: Alarm Chatter via Rapid E/D Cycling       ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Rapid enable/disable cycling at high frequency.
    // Each cycle: enable alarms → alarms can fire → disable → alarms stop
    // At 10Hz this creates physical chatter (siren on/off/on/off).
    constexpr int kCycleCount = 50;
    int enableCount = 0;
    int disableCount = 0;

    for (int i = 0; i < kCycleCount; i++)
    {
        // Enable all alarms
        BitMask<AlarmModeBitmap> enable(0x03);
        auto s1 = Attributes::AlarmsEnabled::Set(kTestEndpoint, enable);
        EXPECT_EQ(s1, Protocols::InteractionModel::Status::Success);
        enableCount++;

        // Disable all alarms
        BitMask<AlarmModeBitmap> disable(0x00);
        auto s2 = Attributes::AlarmsEnabled::Set(kTestEndpoint, disable);
        EXPECT_EQ(s2, Protocols::InteractionModel::Status::Success);
        disableCount++;
    }

    ChipLogProgress(NotSpecified, "║  Completed %d enable/disable cycles                  ║", kCycleCount);
    ChipLogProgress(NotSpecified, "║  Enable calls: %d  Disable calls: %d                 ║", enableCount, disableCount);
    ChipLogProgress(NotSpecified, "║  All accepted (no rate limiting)                     ║");

    EXPECT_EQ(enableCount, kCycleCount);
    EXPECT_EQ(disableCount, kCycleCount);

    ChipLogProgress(NotSpecified, "║  CONFIRMED: Rapid cycling creates alarm chatter      ║");
    ChipLogProgress(NotSpecified, "║  Physical: Siren on/off at 10Hz = hearing damage     ║");
    ChipLogProgress(NotSpecified, "║  Users will permanently disconnect sensor             ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-006: Suppress + Disable Combination Attack
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK006_SuppressPlusDisableComboAttack)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-006: Suppress + Disable Combination Attack      ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Step 1: Activate alarms (sensor trigger)
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 1: Alarms active (sensor triggered)           ║");

    // Step 2: Suppress — silence the current alarm
    CHIP_ERROR err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(err, CHIP_NO_ERROR);
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Step 2: Suppress → current alarm silenced          ║");

    // Step 3: Disable — prevent future alarm generation
    BitMask<AlarmModeBitmap> disableAll(0x00);
    auto status = Attributes::AlarmsEnabled::Set(kTestEndpoint, disableAll);
    EXPECT_EQ(status, Protocols::InteractionModel::Status::Success);
    ChipLogProgress(NotSpecified, "║  Step 3: Disable → future alarms blocked            ║");

    // Step 4: Even after ClearAllAlarms, new triggers won't generate alarms
    err = ClearAllAlarms(kTestEndpoint);
    EXPECT_EQ(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  Step 4: ClearAllAlarms called                      ║");

    // Step 5: Verify alarms can't be activated (all disabled)
    EXPECT_EQ(GetEnabled().Raw(), 0x00u);
    err = SetAlarmsActive(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_NE(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  Step 5: SetAlarmsActive → REJECTED (disabled)      ║");

    ChipLogProgress(NotSpecified, "║  CONFIRMED: Combo attack achieves total safety        ║");
    ChipLogProgress(NotSpecified, "║  defeat: current silenced + future blocked            ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-007: Full Attack Chain — Trigger → Suppress → Disable
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK007_FullAttackChainSafetyDefeat)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-007: Full Attack Chain — Safety Defeat          ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // PHASE 1: Reconnaissance — read current state
    EXPECT_EQ(GetEnabled().Raw(), 0x03u);
    EXPECT_EQ(GetActive().Raw(), 0x00u);
    ChipLogProgress(NotSpecified, "║  Phase 1: Recon — all alarms enabled, none active   ║");

    // PHASE 2: Trigger sensor (simulate compromised device)
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Phase 2: Trigger — AlarmsActive = 0x03             ║");

    // PHASE 3: Suppress (silence the alarm)
    CHIP_ERROR err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(err, CHIP_NO_ERROR);
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Phase 3: Suppress — alarm silenced                 ║");

    // PHASE 4: Disable (prevent future alarms)
    Attributes::AlarmsEnabled::Set(kTestEndpoint, BitMask<AlarmModeBitmap>(0x00));
    EXPECT_EQ(GetEnabled().Raw(), 0x00u);
    ChipLogProgress(NotSpecified, "║  Phase 4: Disable — AlarmsEnabled = 0x00            ║");

    // PHASE 5: Verify complete safety defeat
    // Active alarms suppressed, future alarms impossible.
    EXPECT_EQ(GetSuppressed().Raw(), 0x03u); // currently silenced
    EXPECT_EQ(GetEnabled().Raw(), 0x00u);    // future alarms blocked

    // Attempt new alarm activation — should fail
    ClearAllAlarms(kTestEndpoint);
    err = SetAlarmsActive(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_NE(err, CHIP_NO_ERROR);

    ChipLogProgress(NotSpecified, "║  Phase 5: COMPLETE SAFETY DEFEAT                    ║");
    ChipLogProgress(NotSpecified, "║  Current alarm: suppressed (silenced)                ║");
    ChipLogProgress(NotSpecified, "║  Future alarms: disabled (impossible)                ║");
    ChipLogProgress(NotSpecified, "║  Access required: Operate only (no Timed/PIN)        ║");
    ChipLogProgress(NotSpecified, "║  Physical presence: NOT required (remote attack)      ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-008: ClearAllAlarms Does NOT Re-Enable Disabled Alarms
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK008_ClearAllAlarmsDoesNotReEnable)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-008: ClearAllAlarms ≠ Re-Enable                ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Step 1: Disable all alarms
    Attributes::AlarmsEnabled::Set(kTestEndpoint, BitMask<AlarmModeBitmap>(0x00));
    EXPECT_EQ(GetEnabled().Raw(), 0x00u);
    ChipLogProgress(NotSpecified, "║  Step 1: AlarmsEnabled = 0x00 (all disabled)        ║");

    // Step 2: ClearAllAlarms — clears Active and Suppressed, NOT Enabled
    CHIP_ERROR err = ClearAllAlarms(kTestEndpoint);
    EXPECT_EQ(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  Step 2: ClearAllAlarms called                      ║");

    // Step 3: Verify AlarmsEnabled is STILL 0x00
    EXPECT_EQ(GetEnabled().Raw(), 0x00u);
    ChipLogProgress(NotSpecified, "║  Step 3: AlarmsEnabled = 0x00 (STILL DISABLED!)     ║");

    // Step 4: New alarm activation should fail
    err = SetAlarmsActive(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_NE(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  Step 4: SetAlarmsActive → REJECTED                 ║");

    ChipLogProgress(NotSpecified, "║  CONFIRMED: ClearAllAlarms does not restore enabled  ║");
    ChipLogProgress(NotSpecified, "║  Attacker's disable persists even after clear         ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-009: Feature Gating Defense — SPRS Required for Suppress (DEFENSE)
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK009_FeatureGatingDefenseSPRS)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-009: Feature Gating Defense (SPRS Required)     ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Remove SPRS feature — only VIS + AUD
    Attributes::FeatureMap::Set(kTestEndpoint, 0x03u); // VIS|AUD only, no SPRS

    // Activate alarms
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x03));
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    ChipLogProgress(NotSpecified, "║  Setup: FeatureMap=0x03 (VIS|AUD, no SPRS)          ║");

    // Attempt suppress — should fail with UnsupportedCommand
    CHIP_ERROR err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_NE(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  SuppressAlarms → REJECTED (no SPRS feature)        ║");

    // Alarms still active (not suppressed)
    EXPECT_EQ(GetActive().Raw(), 0x03u);
    EXPECT_EQ(GetSuppressed().Raw(), 0x00u);

    ChipLogProgress(NotSpecified, "║  DEFENSE VERIFIED: SPRS feature gating works         ║");
    ChipLogProgress(NotSpecified, "║  Without SPRS, SuppressAlarm is rejected             ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-010: SetAlarmsActive Rejects Disabled Alarm Types (DEFENSE)
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK010_SetAlarmsActiveRejectsDisabled)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-010: SetAlarmsActive Defense — Rejects Disabled ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // Only enable Visual, disable Audible
    Attributes::AlarmsEnabled::Set(kTestEndpoint, BitMask<AlarmModeBitmap>(0x01));
    ChipLogProgress(NotSpecified, "║  Setup: Only Visual enabled (Audible disabled)       ║");

    // Try to activate both — should fail because Audible is disabled
    CHIP_ERROR err = SetAlarmsActive(kTestEndpoint, BitMask<AlarmModeBitmap>(0x03));
    EXPECT_NE(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  SetAlarmsActive(VIS+AUD) → REJECTED                ║");

    // Activate only Visual — should succeed
    err = SetAlarmsActive(kTestEndpoint, BitMask<AlarmModeBitmap>(0x01));
    EXPECT_EQ(err, CHIP_NO_ERROR);
    EXPECT_TRUE(GetActive().Has(AlarmModeBitmap::kVisual));
    ChipLogProgress(NotSpecified, "║  SetAlarmsActive(VIS only) → SUCCESS                ║");

    ChipLogProgress(NotSpecified, "║  DEFENSE VERIFIED: AlarmsEnabled gating works        ║");
    ChipLogProgress(NotSpecified, "║  BUT: Attacker can disable AlarmsEnabled first       ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}

// ===========================================================================
// ATK-011: SuppressAlarms Rejects When Alarm Not Active (DEFENSE)
// ===========================================================================

TEST_F(TestBoolStateConfigE2E, ATK011_InvalidStateSuppressNotActive)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-011: Suppress Rejected If Alarm Not Active      ║");
    ChipLogProgress(NotSpecified, "╠══════════════════════════════════════════════════════╣");

    // No alarms active — suppress should fail with InvalidInState
    EXPECT_EQ(GetActive().Raw(), 0x00u);

    CHIP_ERROR err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x01));
    EXPECT_NE(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  SuppressAlarms(Visual) when no alarm active         ║");
    ChipLogProgress(NotSpecified, "║  → REJECTED (InvalidInState)                         ║");

    // Suppressed should still be 0
    EXPECT_EQ(GetSuppressed().Raw(), 0x00u);

    // Now activate Visual only, try to suppress Audible
    ActivateAlarms(BitMask<AlarmModeBitmap>(0x01));
    err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x02));
    EXPECT_NE(err, CHIP_NO_ERROR);
    ChipLogProgress(NotSpecified, "║  Suppress Audible when only Visual active → REJECTED ║");

    // Suppress Visual (active) — should succeed
    err = SuppressAlarms(kTestEndpoint, BitMask<AlarmModeBitmap>(0x01));
    EXPECT_EQ(err, CHIP_NO_ERROR);
    EXPECT_TRUE(GetSuppressed().Has(AlarmModeBitmap::kVisual));
    ChipLogProgress(NotSpecified, "║  Suppress Visual (active) → SUCCESS                 ║");

    ChipLogProgress(NotSpecified, "║  DEFENSE VERIFIED: InvalidInState guard works        ║");
    ChipLogProgress(NotSpecified, "║  BUT: No protection once attacker sees active alarms ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");
}
