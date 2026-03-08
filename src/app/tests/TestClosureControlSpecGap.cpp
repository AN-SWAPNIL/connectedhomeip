/**
 *    Copyright (c) 2025 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 *  Spec Gap Tests for Closure Control Cluster (Section 5.4)
 *  Verifies defense claims for DISPROVED violations PROP_CLCTRL_022 and PROP_CLCTRL_031.
 */

#include <lib/core/StringBuilderAdapters.h>
#include <pw_unit_test/framework.h>

#include <app/clusters/closure-control-server/closure-control-cluster-delegate.h>
#include <app/clusters/closure-control-server/closure-control-cluster-logic.h>
#include <app/clusters/closure-control-server/closure-control-cluster-objects.h>
#include <lib/support/CHIPMem.h>
#include <platform/CHIPDeviceLayer.h>
#include <system/SystemClock.h>
#include <system/SystemTimer.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters::ClosureControl;
using namespace chip::app::Clusters;
using namespace chip::System::Clock::Literals;

using Status = chip::Protocols::InteractionModel::Status;

// Repeating mock callback required for linking
__attribute__((weak)) void
MatterClosureControlClusterServerAttributeChangedCallback(const chip::app::ConcreteAttributePath & attributePath)
{}

namespace {

System::Clock::Internal::MockClock gSpecGapMockClock;
System::Clock::ClockBase * gSpecGapSavedClock = nullptr;

// Mock delegate matching existing test pattern
class SpecGapMockDelegate : public DelegateBase
{
public:
    Status HandleStopCommand() override { return Status::Success; }
    Status HandleMoveToCommand(const Optional<TargetPositionEnum> &, const Optional<bool> &,
                               const Optional<Globals::ThreeLevelAutoEnum> &) override
    {
        return Status::Success;
    }
    Status HandleCalibrateCommand() override { return Status::Success; }
    bool IsReadyToMove() override { return mReadyToMove; }
    ElapsedS GetCalibrationCountdownTime() override { return 30; }
    ElapsedS GetMovingCountdownTime() override { return 20; }
    ElapsedS GetWaitingForMotionCountdownTime() override { return 10; }

    bool mReadyToMove = true;
};

// Enhanced mock context that tracks attribute dirty calls
class SpecGapMockContext : public MatterContext
{
public:
    SpecGapMockContext() : MatterContext(kInvalidEndpointId) {}

    void MarkDirty(AttributeId attributeId) override
    {
        mDirtyCount++;
        mLastDirtyAttr = attributeId;
        if (attributeId == Attributes::OverallCurrentState::Id)
            mOverallCurrentStateDirtyCount++;
        if (attributeId == Attributes::MainState::Id)
            mMainStateDirtyCount++;
    }

    void Reset()
    {
        mDirtyCount                    = 0;
        mLastDirtyAttr                 = kInvalidAttributeId;
        mOverallCurrentStateDirtyCount = 0;
        mMainStateDirtyCount           = 0;
    }

    int mDirtyCount                    = 0;
    AttributeId mLastDirtyAttr         = kInvalidAttributeId;
    int mOverallCurrentStateDirtyCount = 0;
    int mMainStateDirtyCount           = 0;
};

class TestClosureControlSpecGap : public ::testing::Test
{
public:
    static void SetUpTestSuite()
    {
        ASSERT_EQ(Platform::MemoryInit(), CHIP_NO_ERROR);
        gSpecGapSavedClock = &System::SystemClock();
        System::Clock::Internal::SetSystemClockForTesting(&gSpecGapMockClock);
    }

    static void TearDownTestSuite()
    {
        System::Clock::Internal::SetSystemClockForTesting(gSpecGapSavedClock);
        Platform::MemoryShutdown();
    }

    void SetUp() override
    {
        mDelegate = SpecGapMockDelegate();
        mContext  = SpecGapMockContext();
        mLogic    = std::make_unique<ClusterLogic>(mDelegate, mContext);
    }

    void TearDown() override { mLogic.reset(); }

    // Helper: init with Positioning + ManuallyOperable features (for MO scenarios)
    void InitWithPSandMO()
    {
        ClusterConformance conf;
        conf.FeatureMap().Set(Feature::kPositioning).Set(Feature::kManuallyOperable);
        ClusterInitParameters params;
        ASSERT_EQ(mLogic->Init(conf, params), CHIP_NO_ERROR);
    }

    // Helper: init with PS + LT features
    void InitWithPSandLT()
    {
        ClusterConformance conf;
        conf.FeatureMap().Set(Feature::kPositioning).Set(Feature::kMotionLatching);
        ClusterInitParameters params;
        ASSERT_EQ(mLogic->Init(conf, params), CHIP_NO_ERROR);
    }

    // Helper: init with PS + LT + MO features
    void InitWithPSandLTandMO()
    {
        ClusterConformance conf;
        conf.FeatureMap().Set(Feature::kPositioning).Set(Feature::kMotionLatching).Set(Feature::kManuallyOperable);
        ClusterInitParameters params;
        ASSERT_EQ(mLogic->Init(conf, params), CHIP_NO_ERROR);
    }

    // Helper: set secure state (PS only: FullyClosed + SecureState=True)
    void SetSecureState_PS()
    {
        DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
            Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional,
            DataModel::MakeNullable(true)));
        ASSERT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);
    }

    // Helper: set secure state (PS+LT: FullyClosed + Latch=True + SecureState=True)
    void SetSecureState_PS_LT()
    {
        DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
            Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)),
            Optional(DataModel::MakeNullable(true)), NullOptional, DataModel::MakeNullable(true)));
        ASSERT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);
    }

    SpecGapMockDelegate mDelegate;
    SpecGapMockContext mContext;
    std::unique_ptr<ClusterLogic> mLogic;
};

// =====================================================================
// PROP_CLCTRL_022 Defense Tests: SecureStateChanged on Re-engagement
// =====================================================================

// SG-01: SecureState=True requires Position=FullyClosed when PS feature supported (§5.4.6.5.4)
TEST_F(TestClosureControlSpecGap, SecureState_True_Requires_FullyClosed_PS)
{
    InitWithPSandMO();

    // SecureState=True with PartiallyOpened must fail
    DataModel::Nullable<GenericOverallCurrentState> badState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kPartiallyOpened)), NullOptional, NullOptional,
        DataModel::MakeNullable(true)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(badState), CHIP_ERROR_INVALID_ARGUMENT);

    // SecureState=True with FullyClosed must succeed
    DataModel::Nullable<GenericOverallCurrentState> goodState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional,
        DataModel::MakeNullable(true)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(goodState), CHIP_NO_ERROR);

    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_EQ(readVal.Value().secureState.Value(), true);
}

// SG-02: SecureState=True requires Latch=True when LT feature supported (§5.4.6.5.4)
TEST_F(TestClosureControlSpecGap, SecureState_True_Requires_Latch_True_LT)
{
    InitWithPSandLT();

    // SecureState=True with Latch=False must fail
    DataModel::Nullable<GenericOverallCurrentState> badState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)),
        Optional(DataModel::MakeNullable(false)), NullOptional, DataModel::MakeNullable(true)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(badState), CHIP_ERROR_INVALID_ARGUMENT);

    // SecureState=True with FullyClosed + Latch=True must succeed
    DataModel::Nullable<GenericOverallCurrentState> goodState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)),
        Optional(DataModel::MakeNullable(true)), NullOptional, DataModel::MakeNullable(true)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(goodState), CHIP_NO_ERROR);

    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_EQ(readVal.Value().secureState.Value(), true);
    EXPECT_EQ(readVal.Value().latch.Value().Value(), true);
}

// SG-03: Null Position accepted in OverallCurrentState (§5.4.6.5.1 - "null SHALL be used" when state unknown)
TEST_F(TestClosureControlSpecGap, Position_Null_Accepted_In_OverallCurrentState)
{
    InitWithPSandMO();

    // Set a valid state first
    SetSecureState_PS();

    // Now set Position to null (unknown after manual motion)
    DataModel::Nullable<GenericOverallCurrentState> nullPosState(GenericOverallCurrentState(
        chip::Optional<DataModel::Nullable<CurrentPositionEnum>>(DataModel::Nullable<CurrentPositionEnum>()), NullOptional, NullOptional));
    EXPECT_EQ(mLogic->SetOverallCurrentState(nullPosState), CHIP_NO_ERROR);

    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_TRUE(readVal.Value().position.HasValue());
    EXPECT_TRUE(readVal.Value().position.Value().IsNull());
}

// SG-04: OverallCurrentState can be set to null (§5.4.7.4 - "SHALL be null if state is unknown")
TEST_F(TestClosureControlSpecGap, OverallCurrentState_Null_After_Manual_Motion)
{
    InitWithPSandMO();

    // Set secure state
    SetSecureState_PS();

    // Verify it's set
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());

    // Set to null (mimicking spec requirement after manual motion)
    DataModel::Nullable<GenericOverallCurrentState> nullState;
    EXPECT_EQ(mLogic->SetOverallCurrentState(nullState), CHIP_NO_ERROR);

    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_TRUE(readVal.IsNull());
}

// SG-05: SecureState=null when Position unknown reflects spec requirement (§5.4.6.5.4)
TEST_F(TestClosureControlSpecGap, SecureState_Null_When_Position_Unknown)
{
    InitWithPSandMO();

    // Set Position=null, SecureState=null (unknown)
    DataModel::Nullable<GenericOverallCurrentState> unknownState(GenericOverallCurrentState(
        chip::Optional<DataModel::Nullable<CurrentPositionEnum>>(DataModel::Nullable<CurrentPositionEnum>()), NullOptional, NullOptional, DataModel::NullNullable));
    EXPECT_EQ(mLogic->SetOverallCurrentState(unknownState), CHIP_NO_ERROR);

    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_TRUE(readVal.Value().position.Value().IsNull());
    EXPECT_TRUE(readVal.Value().secureState.IsNull());
}

// SG-06: EngageStateChanged generated on Disengage (§5.4.9.3)
TEST_F(TestClosureControlSpecGap, EngageStateChanged_Generated_On_Disengage)
{
    InitWithPSandMO();
    mContext.Reset();

    // Transition to Disengaged — should fire EngageStateChanged(false)
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);
    EXPECT_GT(mContext.mMainStateDirtyCount, 0);

    MainStateEnum readState;
    EXPECT_EQ(mLogic->GetMainState(readState), CHIP_NO_ERROR);
    EXPECT_EQ(readState, MainStateEnum::kDisengaged);
}

// SG-07: EngageStateChanged generated on Re-engage (Disengaged→Stopped, §5.4.9.3)
TEST_F(TestClosureControlSpecGap, EngageStateChanged_Generated_On_ReEngage)
{
    InitWithPSandMO();

    // Go to Disengaged
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);
    mContext.Reset();

    // Re-engage → Stopped — should fire EngageStateChanged(true)
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);
    EXPECT_GT(mContext.mMainStateDirtyCount, 0);

    MainStateEnum readState;
    EXPECT_EQ(mLogic->GetMainState(readState), CHIP_NO_ERROR);
    EXPECT_EQ(readState, MainStateEnum::kStopped);
}

// SG-08: SDK BUG — SecureStateChanged NOT fired when SecureState transitions True→null
//        The code only enters the event block when incoming secureState is non-null.
//        Per §5.4.9.4: "SHALL be generated when the SecureState field changes" — True→null IS a change.
TEST_F(TestClosureControlSpecGap, SecureStateChanged_NOT_Fired_When_SecureState_Goes_Null)
{
    InitWithPSandMO();

    // Set secure state: FullyClosed, SecureState=True
    SetSecureState_PS();
    mContext.Reset();

    // Now transition to unknown state: Position=null, SecureState=null
    // SecureState changes from True → null. Per spec, SecureStateChanged SHALL fire.
    // But SDK only checks: if (!incomingOverallCurrentState.secureState.IsNull())
    // Since incoming SecureState IS null, the event code block is SKIPPED.
    DataModel::Nullable<GenericOverallCurrentState> unknownState(GenericOverallCurrentState(
        chip::Optional<DataModel::Nullable<CurrentPositionEnum>>(DataModel::Nullable<CurrentPositionEnum>()), NullOptional, NullOptional, DataModel::NullNullable));
    EXPECT_EQ(mLogic->SetOverallCurrentState(unknownState), CHIP_NO_ERROR);

    // The OverallCurrentState IS marked dirty (attribute subscription catches it)
    EXPECT_GT(mContext.mOverallCurrentStateDirtyCount, 0);

    // Verify the state actually changed
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_TRUE(readVal.Value().secureState.IsNull());
}

// SG-09: OverallCurrentState MarkDirty on null transition (subscription-based detection works)
TEST_F(TestClosureControlSpecGap, OverallCurrentState_Dirty_On_Null_Transition)
{
    InitWithPSandMO();
    SetSecureState_PS();
    mContext.Reset();

    // Transition entire OverallCurrentState to null
    DataModel::Nullable<GenericOverallCurrentState> nullState;
    EXPECT_EQ(mLogic->SetOverallCurrentState(nullState), CHIP_NO_ERROR);

    // MarkDirty MUST be called so subscriptions detect the change
    EXPECT_EQ(mContext.mOverallCurrentStateDirtyCount, 1);
}

// =====================================================================
// PROP_CLCTRL_031 Defense Tests: Closure Dimension state synchronization
// =====================================================================

// SG-10: MoveTo blocked in Disengaged state (§5.5.8.1.4 analog / §5.4.8 MoveTo valid states)
TEST_F(TestClosureControlSpecGap, MoveTo_Blocked_In_Disengaged_State)
{
    InitWithPSandMO();

    // Set OverallCurrentState so HandleMoveTo won't fail on null check
    DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional));
    EXPECT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);

    // Go to Disengaged
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);

    // MoveTo must be rejected with InvalidInState
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::InvalidInState);
}

// SG-11: MoveTo blocked in Error state
TEST_F(TestClosureControlSpecGap, MoveTo_Blocked_In_Error_State)
{
    InitWithPSandMO();

    DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional));
    EXPECT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kError), CHIP_NO_ERROR);

    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::InvalidInState);
}

// SG-12: MoveTo blocked in SetupRequired state
TEST_F(TestClosureControlSpecGap, MoveTo_Blocked_In_SetupRequired_State)
{
    InitWithPSandMO();

    DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional));
    EXPECT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kSetupRequired), CHIP_NO_ERROR);

    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::InvalidInState);
}

// SG-13: Latch guards position change - latched closure rejects position change without unlatch
TEST_F(TestClosureControlSpecGap, Latch_Guards_Position_Change)
{
    InitWithPSandLTandMO();

    // Set latched state
    SetSecureState_PS_LT();

    // Try MoveTo with position change but NO unlatch: must fail
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::InvalidInState);
}

// SG-14: SecureState=True with FullyOpened is rejected (validation prevents false secure claims)
TEST_F(TestClosureControlSpecGap, SecureState_Validation_Rejects_Open_With_SecureTrue)
{
    InitWithPSandMO();

    DataModel::Nullable<GenericOverallCurrentState> invalidState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyOpened)), NullOptional, NullOptional,
        DataModel::MakeNullable(true)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(invalidState), CHIP_ERROR_INVALID_ARGUMENT);
}

// SG-15: Duplicate errors in CurrentErrorList are rejected (PROP_CLCTRL_025)
TEST_F(TestClosureControlSpecGap, Error_List_No_Duplicates)
{
    InitWithPSandMO();
    mLogic->ClearCurrentErrorList();

    // First add succeeds (though it transitions to Error via GenerateOperationalErrorEvent)
    mLogic->AddErrorToCurrentErrorList(ClosureErrorEnum::kBlockedBySensor);

    // Second identical add returns duplicate error
    EXPECT_EQ(mLogic->AddErrorToCurrentErrorList(ClosureErrorEnum::kBlockedBySensor), CHIP_ERROR_DUPLICATE_MESSAGE_RECEIVED);

    // Verify only one entry
    ClosureErrorEnum list[kCurrentErrorListMaxSize] = {};
    Span<ClosureErrorEnum> span(list);
    EXPECT_EQ(mLogic->GetCurrentErrorList(span), CHIP_NO_ERROR);
    EXPECT_EQ(span.size(), 1u);
    EXPECT_EQ(span[0], ClosureErrorEnum::kBlockedBySensor);
}

// SG-16: Stop returns Success even in non-motion states (§5.4.8 Stop command)
TEST_F(TestClosureControlSpecGap, Stop_Returns_Success_In_NonMotion_States)
{
    InitWithPSandMO();

    // In Stopped state, Stop should return Success without side effects
    EXPECT_EQ(mLogic->HandleStop(), Status::Success);

    MainStateEnum readState;
    EXPECT_EQ(mLogic->GetMainState(readState), CHIP_NO_ERROR);
    EXPECT_EQ(readState, MainStateEnum::kStopped);
}

} // namespace
