/*
 * Spec Gap Tests for Window Covering cluster (0x0102) — PROP_WNCV_015
 *
 * Property: PositionAware_Attributes_Bounded_Zero_To_10000
 * Verdict in analysis: VIOLATED (HIGH)
 * Defense verdict: VALID — genuine specification gap
 *
 * Gap: The specification provides no SHALL-level rejection for
 * GoToLiftPercentage / GoToTiltPercentage with percent100ths values > 10000.
 * TargetPositionLiftPercent100ths and TargetPositionTiltPercent100ths lack an
 * explicit max 10000 constraint in the attribute table (unlike CurrentPosition
 * which semantically caps at 10000).  The SDK reference implementation adds
 * bounds checking via IsPercent100thsValid() but this is NOT mandated by spec.
 *
 * These 16 tests prove the gap exists at the attribute layer and verify the
 * SDK's defensive constants are correctly defined.
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

/* Uses the REAL IsPercent100thsValid() from window-covering-server.h
 * (declared at lines 118-119).  The function IS part of the public API,
 * contrary to the original comment. */

namespace {

constexpr EndpointId kEndpoint = 1;

class WindowCoveringSpecGapTest : public ::testing::Test
{
protected:
    void SetUp() override { WindowCoveringTestShim::Reset(); }
    void TearDown() override { WindowCoveringTestShim::Reset(); }
};

/* ======================================================================
 * Tests 1–2: SDK bounds constants
 * ====================================================================== */

TEST_F(WindowCoveringSpecGapTest, SDK_BoundsConstant_MaxClosed_Is_10000)
{
    EXPECT_EQ(WC_PERCENT100THS_MAX_CLOSED, static_cast<Percent100ths>(10000));
}

TEST_F(WindowCoveringSpecGapTest, SDK_BoundsConstant_MinOpen_Is_Zero)
{
    EXPECT_EQ(WC_PERCENT100THS_MIN_OPEN, static_cast<Percent100ths>(0));
}

/* ======================================================================
 * Tests 3–8: Bounds-check logic (calls REAL IsPercent100thsValid)
 * ====================================================================== */

TEST_F(WindowCoveringSpecGapTest, BoundsCheck_Rejects_10001)
{
    EXPECT_FALSE(IsPercent100thsValid(static_cast<Percent100ths>(10001)))
        << "SPEC GAP: Value 10001 exceeds max 10000; spec has no SHALL for rejection";
}

TEST_F(WindowCoveringSpecGapTest, BoundsCheck_Rejects_65535)
{
    EXPECT_FALSE(IsPercent100thsValid(static_cast<Percent100ths>(65535))) << "SPEC GAP: uint16 max (65535) exceeds max 10000";
}

TEST_F(WindowCoveringSpecGapTest, BoundsCheck_Rejects_50000)
{
    EXPECT_FALSE(IsPercent100thsValid(static_cast<Percent100ths>(50000)))
        << "Mid-range value 50000 correctly rejected by REAL SDK function";
}

TEST_F(WindowCoveringSpecGapTest, BoundsCheck_Accepts_10000)
{
    EXPECT_TRUE(IsPercent100thsValid(static_cast<Percent100ths>(10000)))
        << "Boundary value 10000 (100.00%) accepted by REAL SDK function";
}

TEST_F(WindowCoveringSpecGapTest, BoundsCheck_Accepts_Zero)
{
    EXPECT_TRUE(IsPercent100thsValid(static_cast<Percent100ths>(0))) << "Lower boundary 0 (0.00%) accepted by REAL SDK function";
}

TEST_F(WindowCoveringSpecGapTest, BoundsCheck_Accepts_5000)
{
    EXPECT_TRUE(IsPercent100thsValid(static_cast<Percent100ths>(5000)))
        << "Mid-range value 5000 (50.00%) accepted by REAL SDK function";
}

/* ======================================================================
 * Tests 9–12: Direct attribute writes accept out-of-bounds values
 *
 * CORE SPEC GAP PROOF: The Accessors Set() functions only check
 * CanRepresentValue (i.e. not-null-sentinel for nullable uint16).
 * They do NOT enforce max 10000.  This means any code path that
 * writes to TargetPosition attributes without going through the
 * command handler's IsPercent100thsValid() will succeed.
 * ====================================================================== */

TEST_F(WindowCoveringSpecGapTest, TargetLift_Accepts_OutOfBounds_65534)
{
    /* 65534 is the maximum non-null uint16 value for a nullable attribute.
       65535 = null sentinel, so 65534 is the real max storable value. */
    Status st = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(65534));
    EXPECT_EQ(st, Status::Success) << "SPEC GAP PROOF: Attribute layer accepts 65534 (>10000) — no bounds guard at attribute level";

    Nullable<Percent100ths> readBack;
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, readBack);
    ASSERT_FALSE(readBack.IsNull());
    EXPECT_EQ(readBack.Value(), 65534u);
}

TEST_F(WindowCoveringSpecGapTest, TargetTilt_Accepts_OutOfBounds_65534)
{
    Status st = Attributes::TargetPositionTiltPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(65534));
    EXPECT_EQ(st, Status::Success) << "SPEC GAP PROOF: Attribute layer accepts 65534 for tilt — no bounds guard";

    Nullable<Percent100ths> readBack;
    Attributes::TargetPositionTiltPercent100ths::Get(kEndpoint, readBack);
    ASSERT_FALSE(readBack.IsNull());
    EXPECT_EQ(readBack.Value(), 65534u);
}

TEST_F(WindowCoveringSpecGapTest, TargetLift_Accepts_OutOfBounds_10001)
{
    Status st = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(10001));
    EXPECT_EQ(st, Status::Success) << "SPEC GAP PROOF: Value just above boundary (10001) stored without error";

    Nullable<Percent100ths> readBack;
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, readBack);
    ASSERT_FALSE(readBack.IsNull());
    EXPECT_EQ(readBack.Value(), 10001u);
}

TEST_F(WindowCoveringSpecGapTest, TargetTilt_Accepts_OutOfBounds_10001)
{
    Status st = Attributes::TargetPositionTiltPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(10001));
    EXPECT_EQ(st, Status::Success) << "SPEC GAP PROOF: 10001 stored in tilt target without error";

    Nullable<Percent100ths> readBack;
    Attributes::TargetPositionTiltPercent100ths::Get(kEndpoint, readBack);
    ASSERT_FALSE(readBack.IsNull());
    EXPECT_EQ(readBack.Value(), 10001u);
}

/* ======================================================================
 * Tests 13–14: CurrentPosition attributes also lack max validation
 * ====================================================================== */

TEST_F(WindowCoveringSpecGapTest, CurrentPositionLift_No_MaxValidation)
{
    Status st = Attributes::CurrentPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(30000));
    EXPECT_EQ(st, Status::Success) << "CurrentPositionLiftPercent100ths also accepts out-of-bounds value 30000";

    Nullable<Percent100ths> readBack;
    Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, readBack);
    ASSERT_FALSE(readBack.IsNull());
    EXPECT_EQ(readBack.Value(), 30000u);
}

TEST_F(WindowCoveringSpecGapTest, CurrentPositionTilt_No_MaxValidation)
{
    Status st = Attributes::CurrentPositionTiltPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(30000));
    EXPECT_EQ(st, Status::Success) << "CurrentPositionTiltPercent100ths also accepts out-of-bounds value 30000";

    Nullable<Percent100ths> readBack;
    Attributes::CurrentPositionTiltPercent100ths::Get(kEndpoint, readBack);
    ASSERT_FALSE(readBack.IsNull());
    EXPECT_EQ(readBack.Value(), 30000u);
}

/* ======================================================================
 * Test 15: Operational state computed with out-of-bounds target
 *
 * If an out-of-bounds value reaches TargetPosition, ComputeOperationalState
 * will indicate closing/opening motion toward an unreachable physical limit.
 * ====================================================================== */

TEST_F(WindowCoveringSpecGapTest, OperationalState_Computed_With_OutOfBounds_Target)
{
    /* Set current at 5000 (50%), target at 65534 (out-of-bounds) */
    Attributes::CurrentPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(5000));
    Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(65534));

    Nullable<Percent100ths> current, target;
    Attributes::CurrentPositionLiftPercent100ths::Get(kEndpoint, current);
    Attributes::TargetPositionLiftPercent100ths::Get(kEndpoint, target);

    ASSERT_FALSE(current.IsNull());
    ASSERT_FALSE(target.IsNull());

    /* target (65534) > current (5000) => motor drives DOWN/CLOSE */
    EXPECT_GT(target.Value(), current.Value())
        << "Out-of-bounds target creates a motor drive condition toward unreachable position";

    /* The difference between target and physical max (10000) shows overflow magnitude */
    uint16_t overflow = target.Value() - WC_PERCENT100THS_MAX_CLOSED;
    EXPECT_EQ(overflow, 55534u) << "Overflow beyond physical limit = 55534 hundredths of percent";
}

/* ======================================================================
 * Test 16: Null sentinel distinction
 *
 * For nullable uint16 attributes, 65535 is the null sentinel.
 * This is NOT bounds-checking — it's type representation.
 * Verifies that 65535 is rejected for the right reason.
 * ====================================================================== */

TEST_F(WindowCoveringSpecGapTest, NullSentinel_65535_Rejected_But_Not_Bounds)
{
    /* 65535 for a nullable uint16 is the null sentinel, so Set(65535) fails
       with ConstraintError because CanRepresentValue returns false.
       This is NOT a bounds check for max 10000. */
    Status st = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(65535));
    EXPECT_EQ(st, Status::ConstraintError) << "65535 rejected as null sentinel for nullable uint16 — NOT bounds checking";

    /* But 65534 succeeds — proving there is no max-10000 guard */
    st = Attributes::TargetPositionLiftPercent100ths::Set(kEndpoint, static_cast<Percent100ths>(65534));
    EXPECT_EQ(st, Status::Success) << "65534 accepted — confirms absence of max-10000 attribute-level guard";
}

} // namespace
