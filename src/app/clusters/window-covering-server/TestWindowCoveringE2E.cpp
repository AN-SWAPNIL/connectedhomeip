/*
 * E2E Attack Simulation Tests for Window Covering cluster (0x0102)
 *
 * Property: PROP_WNCV_015 — PositionAware_Attributes_Bounded_Zero_To_10000
 *
 * Attack scenario from vulnerability analysis:
 *   1. Device at 50% (CurrentPositionLiftPercent100ths = 5000)
 *   2. Attacker sends GoToLiftPercentage with value 65535 (or any > 10000)
 *   3. TargetPositionLiftPercent100ths set to out-of-bounds value
 *   4. Motor drives toward position > physical closed limit (10000)
 *   5. Motor stalls against end-stop → mechanical damage
 *
 * The SDK mitigates this via IsPercent100thsValid() in command handlers,
 * but the spec gap means non-SDK implementations may be vulnerable.
 *
 * These 11 E2E tests simulate the attack at the attribute layer and verify
 * both the vulnerability path and the SDK's mitigation.
 */

#include "window-covering-server.h"
#include "window_covering_attr_shim.h"

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app/data-model/Nullable.h>
#include <lib/core/DataModelTypes.h>
#include <protocols/interaction_model/StatusCode.h>

#include <pw_unit_test/framework.h>

using namespace chip;
using namespace chip::app::Clusters::WindowCovering;
using chip::app::DataModel::Nullable;
using chip::Protocols::InteractionModel::Status;

/* Bounds check matching the SDK's IsPercent100thsValid() logic */
#define CHECK_BOUNDS_INVALID(MIN, VAL, MAX) ((VAL < MIN) || (VAL > MAX))
#define CHECK_BOUNDS_VALID(MIN, VAL, MAX) (!CHECK_BOUNDS_INVALID(MIN, VAL, MAX))

static bool SimulateIsPercent100thsValid(Percent100ths v)
{
    return CHECK_BOUNDS_VALID(WC_PERCENT100THS_MIN_OPEN, v, WC_PERCENT100THS_MAX_CLOSED);
}

namespace {

constexpr EndpointId kEndpoint = 1;

class WindowCoveringE2EAttackTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        WindowCoveringTestShim::Reset();

        /* Establish normal operational state: covering at 50% */
        Attributes::CurrentPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(5000));
        Attributes::CurrentPositionTiltPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(5000));
        Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(5000));
        Attributes::TargetPositionTiltPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(5000));
    }

    void TearDown() override { WindowCoveringTestShim::Reset(); }
};

/* ======================================================================
 * Test 1: Motor over-travel attack — Lift axis
 *
 * Simulates the direct-write path: if an implementation sets
 * TargetPositionLiftPercent100ths without the SDK's bounds check,
 * the motor drives to an unreachable position.
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, MotorOverTravel_Attack_Lift_65534)
{
    /* ATTACK: Write out-of-bounds target directly */
    const Percent100ths attackPayload = 65534;
    Status st                         = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, attackPayload);
    ASSERT_EQ(st, Status::Success) << "Attack payload written to TargetPositionLift";

    /* VERIFY: Target holds the out-of-bounds value */
    Nullable<Percent100ths> target;
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, target);
    ASSERT_FALSE(target.IsNull());
    EXPECT_EQ(target.Value(), 65534u);

    /* VERIFY: Motor would compute MovingDownOrClose (target > current) */
    Nullable<Percent100ths> current;
    Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, current);
    ASSERT_FALSE(current.IsNull());
    EXPECT_LT(current.Value(), target.Value()) << "ATTACK SUCCESS: Motor drives toward unreachable target 65534 from current 5000";

    /* VERIFY: Physical overflow */
    uint16_t physicalOverflow = target.Value() - WC_PERCENT100THS_MAX_CLOSED;
    EXPECT_EQ(physicalOverflow, 55534u) << "Motor would attempt to travel 55534/100 = 555.34% beyond physical closed limit";
}

/* ======================================================================
 * Test 2: Motor over-travel attack — Tilt axis
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, MotorOverTravel_Attack_Tilt_65534)
{
    const Percent100ths attackPayload = 65534;
    Status st                         = Attributes::TargetPositionTiltPercent100ths::Set(kEndpoint, attackPayload);
    ASSERT_EQ(st, Status::Success);

    Nullable<Percent100ths> target;
    Attributes::TargetPositionTiltPercent100ths::Get(kEndpoint, target);
    ASSERT_FALSE(target.IsNull());
    EXPECT_EQ(target.Value(), 65534u) << "ATTACK SUCCESS: Tilt target set beyond physical limit";
}

/* ======================================================================
 * Test 3: Position tracking inconsistency
 *
 * After attack, CurrentPosition stays at valid value while
 * TargetPosition is beyond physical limit → position tracking
 * diverges, causing indefinite motor operation.
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, PositionTracking_Inconsistency)
{
    /* Attack: set target beyond physical limit */
    Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(40000));

    /* Simulate motor reaching physical closed limit */
    Attributes::CurrentPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(10000));

    Nullable<Percent100ths> current, target;
    Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, current);
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, target);

    ASSERT_FALSE(current.IsNull());
    ASSERT_FALSE(target.IsNull());

    /* Motor at physical limit (10000) but target says 40000 → motor keeps trying */
    EXPECT_NE(current.Value(), target.Value()) << "ATTACK: Position tracking diverged — motor stalls indefinitely";
    EXPECT_EQ(current.Value(), 10000u);
    EXPECT_EQ(target.Value(), 40000u);

    /* Gap between current and target causes continuous motor drive */
    uint16_t stallGap = target.Value() - current.Value();
    EXPECT_EQ(stallGap, 30000u) << "30000 hundredths gap = motor stall condition (target unreachable)";
}

/* ======================================================================
 * Test 4: Operational state drives motor beyond limit
 *
 * ComputeOperationalState uses raw uint16 comparison.
 * With out-of-bounds target, it computes MovingDownOrClose
 * even after reaching the physical end-stop.
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, OperationalState_Drives_Beyond_Limit)
{
    /* Device at physical closed limit */
    Attributes::CurrentPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(10000));
    /* Attack: target beyond limit */
    Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(50000));

    Nullable<Percent100ths> current, target;
    Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, current);
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, target);

    ASSERT_FALSE(current.IsNull());
    ASSERT_FALSE(target.IsNull());

    /* Operational state logic: target > current → still "closing" */
    bool motorWouldClose = (target.Value() > current.Value());
    EXPECT_TRUE(motorWouldClose) << "ATTACK: Even at physical limit (10000), motor computes 'still closing' toward 50000";
}

/* ======================================================================
 * Test 5: Maximum uint16 attack — both axes simultaneously
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, MaxUint16_Attack_Both_Axes)
{
    const Percent100ths maxNonNull = 65534;

    Status stLift = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, maxNonNull);
    Status stTilt = Attributes::TargetPositionTiltPercent100ths::Set(kEndpoint, maxNonNull);
    EXPECT_EQ(stLift, Status::Success);
    EXPECT_EQ(stTilt, Status::Success);

    Nullable<Percent100ths> liftTarget, tiltTarget;
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, liftTarget);
    Attributes::TargetPositionTiltPercent100ths::Get(kEndpoint, tiltTarget);

    ASSERT_FALSE(liftTarget.IsNull());
    ASSERT_FALSE(tiltTarget.IsNull());
    EXPECT_EQ(liftTarget.Value(), maxNonNull);
    EXPECT_EQ(tiltTarget.Value(), maxNonNull);

    /* Both axes would drive simultaneously beyond physical limits */
    Nullable<Percent100ths> liftCurrent, tiltCurrent;
    Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, liftCurrent);
    Attributes::CurrentPositionTiltPercent100ths::Get(kEndpoint, tiltCurrent);

    EXPECT_LT(liftCurrent.Value(), liftTarget.Value());
    EXPECT_LT(tiltCurrent.Value(), tiltTarget.Value());
}

/* ======================================================================
 * Test 6: Boundary probing — 10000 vs 10001
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, BoundaryProbe_10000_vs_10001)
{
    /* 10000 should be the maximum valid value */
    Status st10000 = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(10000));
    EXPECT_EQ(st10000, Status::Success) << "10000 (100.00%) accepted — within physical range";

    /* 10001 also succeeds at attribute level — SPEC GAP */
    Status st10001 = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(10001));
    EXPECT_EQ(st10001, Status::Success) << "SPEC GAP: 10001 accepted at attribute layer — no max constraint";

    Nullable<Percent100ths> readBack;
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, readBack);
    ASSERT_FALSE(readBack.IsNull());
    EXPECT_EQ(readBack.Value(), 10001u);
}

/* ======================================================================
 * Tests 7–8: SDK mitigation — IsPercent100thsValid blocks attack
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, SDK_Mitigation_Blocks_Lift_Attack)
{
    /* Simulate what the SDK command handler does for GoToLiftPercentage */
    Percent100ths attackPayload = 65534;

    bool sdkAllows = SimulateIsPercent100thsValid(attackPayload);
    EXPECT_FALSE(sdkAllows) << "SDK mitigation: IsPercent100thsValid(65534) returns false → ConstraintError in command handler";

    /* If not blocked, the attribute write would succeed: */
    Status directWrite = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, attackPayload);
    EXPECT_EQ(directWrite, Status::Success) << "Confirms attack succeeds if SDK bounds check is bypassed";
}

TEST_F(WindowCoveringE2EAttackTest, SDK_Mitigation_Blocks_Tilt_Attack)
{
    Percent100ths attackPayload = 65534;

    bool sdkAllows = SimulateIsPercent100thsValid(attackPayload);
    EXPECT_FALSE(sdkAllows) << "SDK mitigation: Tilt axis equally protected by IsPercent100thsValid";
}

/* ======================================================================
 * Test 9: SDK mitigation boundary precision
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, SDK_Mitigation_Boundary_Precision)
{
    /* 10000 is the last valid value */
    EXPECT_TRUE(SimulateIsPercent100thsValid(10000)) << "10000 = 100.00% — maximum valid closed position";

    /* 10001 is the first invalid value */
    EXPECT_FALSE(SimulateIsPercent100thsValid(10001)) << "10001 = 100.01% — first invalid value, blocked by SDK";

    /* Common attack values */
    EXPECT_FALSE(SimulateIsPercent100thsValid(20000));
    EXPECT_FALSE(SimulateIsPercent100thsValid(32768));
    EXPECT_FALSE(SimulateIsPercent100thsValid(65534));
}

/* ======================================================================
 * Test 10: Sequential attack — multiple values, all blocked by SDK
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, Sequential_Attack_All_Blocked)
{
    const Percent100ths attackValues[] = { 10001, 15000, 20000, 32767, 50000, 65534 };

    for (auto val : attackValues)
    {
        /* SDK command handler would block each value */
        EXPECT_FALSE(SimulateIsPercent100thsValid(val)) << "SDK blocks attack value " << val;

        /* But direct attribute write succeeds for all except null sentinel */
        Status st = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, val);
        EXPECT_EQ(st, Status::Success) << "SPEC GAP: Attribute layer accepts " << val;
    }
}

/* ======================================================================
 * Test 11: Partial overflow — 50001 attack showing intermediate damage
 * ====================================================================== */

TEST_F(WindowCoveringE2EAttackTest, PartialOverflow_50001_Attack)
{
    /* Attack with value 50001 — 5x beyond physical limit */
    Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(50001));

    /* Simulate motor reaching physical closed limit */
    Attributes::CurrentPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(10000));

    Nullable<Percent100ths> current, target;
    Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, current);
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, target);

    ASSERT_FALSE(current.IsNull());
    ASSERT_FALSE(target.IsNull());

    /* Motor at physical limit but target says go further */
    uint16_t overflow = target.Value() - current.Value();
    EXPECT_EQ(overflow, 40001u) << "Motor stall: 400.01% beyond physical position, motor burnout risk";

    /* SDK would have blocked this */
    EXPECT_FALSE(SimulateIsPercent100thsValid(50001)) << "SDK mitigation would have prevented this attack";
}

} // namespace
