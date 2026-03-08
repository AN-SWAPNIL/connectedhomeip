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
 *  E2E Attack Simulation Tests for Closure Control Cluster (Section 5.4)
 *  Simulates PROP_CLCTRL_022 and PROP_CLCTRL_031 attack scenarios against SDK implementation.
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

System::Clock::Internal::MockClock gAttackMockClock;
System::Clock::ClockBase * gAttackSavedClock = nullptr;

// Configurable mock delegate for attack simulation
class AttackMockDelegate : public DelegateBase
{
public:
    Status HandleStopCommand() override { return mStopResult; }
    Status HandleMoveToCommand(const Optional<TargetPositionEnum> & pos, const Optional<bool> & latch,
                               const Optional<Globals::ThreeLevelAutoEnum> & speed) override
    {
        mLastMoveToPos = pos;
        mMoveToCallCount++;
        return mMoveToResult;
    }
    Status HandleCalibrateCommand() override { return Status::Success; }
    bool IsReadyToMove() override { return mReadyToMove; }
    ElapsedS GetCalibrationCountdownTime() override { return 30; }
    ElapsedS GetMovingCountdownTime() override { return 20; }
    ElapsedS GetWaitingForMotionCountdownTime() override { return 10; }

    bool mReadyToMove       = true;
    Status mStopResult      = Status::Success;
    Status mMoveToResult    = Status::Success;
    int mMoveToCallCount    = 0;
    Optional<TargetPositionEnum> mLastMoveToPos;
};

// Enhanced mock context tracking dirty calls per attribute
class AttackMockContext : public MatterContext
{
public:
    AttackMockContext() : MatterContext(kInvalidEndpointId) {}

    void MarkDirty(AttributeId attributeId) override
    {
        mDirtyCount++;
        mLastDirtyAttr = attributeId;
        if (attributeId == Attributes::OverallCurrentState::Id)
            mOverallCurrentStateDirtyCount++;
        if (attributeId == Attributes::MainState::Id)
            mMainStateDirtyCount++;
        if (attributeId == Attributes::OverallTargetState::Id)
            mTargetStateDirtyCount++;
    }

    void Reset()
    {
        mDirtyCount                    = 0;
        mLastDirtyAttr                 = kInvalidAttributeId;
        mOverallCurrentStateDirtyCount = 0;
        mMainStateDirtyCount           = 0;
        mTargetStateDirtyCount         = 0;
    }

    int mDirtyCount                    = 0;
    AttributeId mLastDirtyAttr         = kInvalidAttributeId;
    int mOverallCurrentStateDirtyCount = 0;
    int mMainStateDirtyCount           = 0;
    int mTargetStateDirtyCount         = 0;
};

class TestClosureControlAttackSim : public ::testing::Test
{
public:
    static void SetUpTestSuite()
    {
        ASSERT_EQ(Platform::MemoryInit(), CHIP_NO_ERROR);
        gAttackSavedClock = &System::SystemClock();
        System::Clock::Internal::SetSystemClockForTesting(&gAttackMockClock);
    }

    static void TearDownTestSuite()
    {
        System::Clock::Internal::SetSystemClockForTesting(gAttackSavedClock);
        Platform::MemoryShutdown();
    }

    void SetUp() override
    {
        mDelegate = AttackMockDelegate();
        mContext  = AttackMockContext();
        mLogic    = std::make_unique<ClusterLogic>(mDelegate, mContext);
    }

    void TearDown() override { mLogic.reset(); }

    // Helper: Full-feature init (PS + LT + MO)
    void InitFullFeature()
    {
        ClusterConformance conf;
        conf.FeatureMap().Set(Feature::kPositioning).Set(Feature::kMotionLatching).Set(Feature::kManuallyOperable);
        ClusterInitParameters params;
        ASSERT_EQ(mLogic->Init(conf, params), CHIP_NO_ERROR);
    }

    // Helper: PS + MO init
    void InitPSandMO()
    {
        ClusterConformance conf;
        conf.FeatureMap().Set(Feature::kPositioning).Set(Feature::kManuallyOperable);
        ClusterInitParameters params;
        ASSERT_EQ(mLogic->Init(conf, params), CHIP_NO_ERROR);
    }

    // Helper: Set the closure to fully-closed, secure state
    void MakeSecure_PS()
    {
        DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
            Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional,
            DataModel::MakeNullable(true)));
        ASSERT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);
    }

    void MakeSecure_PS_LT()
    {
        DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
            Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)),
            Optional(DataModel::MakeNullable(true)), NullOptional, DataModel::MakeNullable(true)));
        ASSERT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);
    }

    AttackMockDelegate mDelegate;
    AttackMockContext mContext;
    std::unique_ptr<ClusterLogic> mLogic;
};

// =================================================================
// ATTACK 1: PROP_CLCTRL_022 — Stale SecureState after re-engagement
// =================================================================

// E2E-01: Full attack path with COMPLIANT delegate — delegate correctly nulls state after re-engage
// Attack scenario: Closed+Secure → Disengage → manual open → Re-engage → delegate sets null
// Expected: OverallCurrentState updates to unknown, subscription detects change
TEST_F(TestClosureControlAttackSim, Attack_PROP022_CompliantDelegate_NullsStateAfterReEngage)
{
    InitPSandMO();

    // Step 1: Closure is Stopped, FullyClosed, SecureState=True
    MakeSecure_PS();
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);

    // Verify secure
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_EQ(readVal.Value().secureState.Value(), true);

    // Step 2: Emergency release → Disengaged
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);

    // Step 3: Attacker manually opens the closure (physical, no electronic tracking)
    // SDK has no knowledge — this is a physical-only action

    // Step 4: Attacker re-engages → Stopped
    mContext.Reset();
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);
    EXPECT_GT(mContext.mMainStateDirtyCount, 0); // MainState change detected

    // Step 5: COMPLIANT delegate sets OverallCurrentState to reflect unknown position
    // Per §5.4.6.5.1: Position=null when state unknown after manual motion
    mContext.Reset();
    DataModel::Nullable<GenericOverallCurrentState> unknownState(GenericOverallCurrentState(
        chip::Optional<DataModel::Nullable<CurrentPositionEnum>>(DataModel::Nullable<CurrentPositionEnum>()), NullOptional, NullOptional, DataModel::NullNullable));
    EXPECT_EQ(mLogic->SetOverallCurrentState(unknownState), CHIP_NO_ERROR);

    // Verify: OverallCurrentState IS marked dirty → subscription-based monitoring detects it
    EXPECT_EQ(mContext.mOverallCurrentStateDirtyCount, 1);

    // Verify: State reflects unknown position and unknown secure state
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_TRUE(readVal.Value().position.Value().IsNull()); // Position unknown
    EXPECT_TRUE(readVal.Value().secureState.IsNull());       // SecureState unknown

    // FINDING: SecureStateChanged event NOT generated (SDK gap — only fires for non-null incoming)
    // But subscription-based monitoring DOES detect the attribute change via MarkDirty.
    // Attack is PARTIALLY MITIGATED: subscription listeners catch it, event listeners do not.
}

// E2E-02: NON-COMPLIANT delegate — keeps stale state after re-engage (attack succeeds)
TEST_F(TestClosureControlAttackSim, Attack_PROP022_NonCompliantDelegate_StaleState)
{
    InitPSandMO();

    // Step 1: Secure state
    MakeSecure_PS();

    // Step 2: Disengage
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);

    // Step 3: Physical manual open (no electronic tracking)

    // Step 4: Re-engage → Stopped (non-compliant: delegate does NOT update OverallCurrentState)
    mContext.Reset();
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);

    // NON-COMPLIANT: Delegate never calls SetOverallCurrentState.
    // No OverallCurrentState dirty flag set (only MainState was set)
    EXPECT_EQ(mContext.mOverallCurrentStateDirtyCount, 0);

    // SecureState remains stale True — attacker succeeds in this non-compliant implementation
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_EQ(readVal.Value().secureState.Value(), true);          // STALE — still claims secure
    EXPECT_EQ(readVal.Value().position.Value().Value(), CurrentPositionEnum::kFullyClosed); // STALE
}

// E2E-03: Re-engagement lifecycle — full Stopped→Disengaged→Stopped transition with event tracking
TEST_F(TestClosureControlAttackSim, Attack_PROP022_ReEngagementLifecycle)
{
    InitPSandMO();
    MakeSecure_PS();

    // Track: Stopped → Disengaged fires EngageStateChanged(false)
    mContext.Reset();
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);
    EXPECT_GT(mContext.mMainStateDirtyCount, 0);

    // Track: Disengaged → Stopped fires EngageStateChanged(true)
    mContext.Reset();
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);
    EXPECT_GT(mContext.mMainStateDirtyCount, 0);

    MainStateEnum state;
    EXPECT_EQ(mLogic->GetMainState(state), CHIP_NO_ERROR);
    EXPECT_EQ(state, MainStateEnum::kStopped);
}

// E2E-04: SecureState True→Null event gap — demonstrates SDK limitation
TEST_F(TestClosureControlAttackSim, Attack_PROP022_SecureState_True_To_Null_EventGap)
{
    InitPSandMO();

    // Set SecureState=True
    MakeSecure_PS();
    mContext.Reset();

    // Transition to SecureState=False: This SHOULD trigger SecureStateChanged
    DataModel::Nullable<GenericOverallCurrentState> falseState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyOpened)), NullOptional, NullOptional,
        DataModel::MakeNullable(false)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(falseState), CHIP_NO_ERROR);
    EXPECT_EQ(mContext.mOverallCurrentStateDirtyCount, 1); // Attribute IS dirty

    // Now test: SecureState=False → SecureState=null
    mContext.Reset();
    DataModel::Nullable<GenericOverallCurrentState> nullSecState(GenericOverallCurrentState(
        chip::Optional<DataModel::Nullable<CurrentPositionEnum>>(DataModel::Nullable<CurrentPositionEnum>()), NullOptional, NullOptional, DataModel::NullNullable));
    EXPECT_EQ(mLogic->SetOverallCurrentState(nullSecState), CHIP_NO_ERROR);
    EXPECT_EQ(mContext.mOverallCurrentStateDirtyCount, 1); // Attribute IS dirty

    // Verify final state: SecureState is null
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_TRUE(readVal.Value().secureState.IsNull());
}

// E2E-05: Subscription-based detection — MarkDirty catches what events miss
TEST_F(TestClosureControlAttackSim, Attack_PROP022_SubscriptionBased_Detection)
{
    InitPSandMO();
    MakeSecure_PS();
    mContext.Reset();

    // Complete re-engagement cycle with compliant delegate
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);

    // Delegate properly updates OverallCurrentState to null (compliant)
    DataModel::Nullable<GenericOverallCurrentState> nullState;
    EXPECT_EQ(mLogic->SetOverallCurrentState(nullState), CHIP_NO_ERROR);

    // Subscription-based: OverallCurrentState was marked dirty
    EXPECT_GT(mContext.mOverallCurrentStateDirtyCount, 0);
    // MainState was marked dirty (Stopped→Disengaged→Stopped)
    EXPECT_GT(mContext.mMainStateDirtyCount, 0);

    // A Matter subscription listener for OverallCurrentState will receive the update
    // and can detect that the closure is no longer in a known secure state.
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_TRUE(readVal.IsNull());
}

// =================================================================
// ATTACK 2: PROP_CLCTRL_031 — Closure Dimension bypass
// =================================================================

// E2E-06: Compliant cross-cluster update — MoveTo + OverallCurrentState update
TEST_F(TestClosureControlAttackSim, Attack_PROP031_MoveToChangesState_Compliant)
{
    InitPSandMO();
    MakeSecure_PS();

    // Simulate Closure Dimension SetTarget causing movement via Closure Control MoveTo
    // Per §5.4.4: "Implementers SHALL ensure... properly integrated and reflected"
    mContext.Reset();
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::Success);

    // Verify: MainState transitioned to Moving
    MainStateEnum state;
    EXPECT_EQ(mLogic->GetMainState(state), CHIP_NO_ERROR);
    EXPECT_EQ(state, MainStateEnum::kMoving);

    // Simulate movement completion: delegate updates OverallCurrentState
    DataModel::Nullable<GenericOverallCurrentState> openState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyOpened)), NullOptional, NullOptional,
        DataModel::MakeNullable(false)));
    mContext.Reset();
    EXPECT_EQ(mLogic->SetOverallCurrentState(openState), CHIP_NO_ERROR);

    // SecureState changed True→False and OverallCurrentState is dirty
    EXPECT_GT(mContext.mOverallCurrentStateDirtyCount, 0);

    // Verify final state: FullyOpened, SecureState=False
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_EQ(readVal.Value().position.Value().Value(), CurrentPositionEnum::kFullyOpened);
    EXPECT_EQ(readVal.Value().secureState.Value(), false);
}

// E2E-07: Attack: movement without updating OverallCurrentState (non-compliant delegate)
TEST_F(TestClosureControlAttackSim, Attack_PROP031_MoveToWithoutStateUpdate)
{
    InitPSandMO();
    MakeSecure_PS();

    // Attacker sends MoveTo to open
    mContext.Reset();
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::Success);

    // Movement happens physically, but non-compliant delegate NEVER updates OverallCurrentState
    // Only MainState and OverallTargetState were updated by HandleMoveTo itself
    EXPECT_GT(mContext.mMainStateDirtyCount, 0);
    EXPECT_GT(mContext.mTargetStateDirtyCount, 0);

    // OverallCurrentState still shows the old secure state unless delegate updates it
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_FALSE(readVal.IsNull());
    EXPECT_EQ(readVal.Value().secureState.Value(), true);          // STALE — still claims secure
    EXPECT_EQ(readVal.Value().position.Value().Value(), CurrentPositionEnum::kFullyClosed); // STALE

    // However: OverallTargetState correctly shows the open target
    DataModel::Nullable<GenericOverallTargetState> targetVal;
    EXPECT_EQ(mLogic->GetOverallTargetState(targetVal), CHIP_NO_ERROR);
    EXPECT_FALSE(targetVal.IsNull());
    EXPECT_EQ(targetVal.Value().position.Value().Value(), TargetPositionEnum::kMoveToFullyOpen);
    // A monitoring system checking OverallTargetState vs OverallCurrentState would detect the mismatch
}

// E2E-08: Disengaged blocks MoveTo (§5.5.8.1.4 analog — SetTarget blocked in Disengaged)
TEST_F(TestClosureControlAttackSim, Attack_PROP031_DisengagedBlocksMoveTo)
{
    InitPSandMO();

    DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional));
    EXPECT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);

    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kDisengaged), CHIP_NO_ERROR);

    mContext.Reset();
    mDelegate.mMoveToCallCount = 0;

    // Attack: try to move while disengaged — must fail
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::InvalidInState);

    // Delegate was never even called
    EXPECT_EQ(mDelegate.mMoveToCallCount, 0);
}

// E2E-09: Latch enforcement prevents unauthorized position changes
TEST_F(TestClosureControlAttackSim, Attack_PROP031_LatchEnforcement)
{
    InitFullFeature();

    // Set latched + secure state
    MakeSecure_PS_LT();

    mContext.Reset();
    mDelegate.mMoveToCallCount = 0;

    // Attack: try to open without unlatching
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::InvalidInState);

    // Delegate not called — latch guard rejected the command at ClusterLogic level
    EXPECT_EQ(mDelegate.mMoveToCallCount, 0);

    // State unchanged — still secure
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_EQ(readVal.Value().secureState.Value(), true);
}

// E2E-10: Full lifecycle — FullyClosed+Secure → MoveTo Open → Stopped → re-secure
TEST_F(TestClosureControlAttackSim, Attack_PROP031_FullLifecycle_Secure_To_Open_To_Secure)
{
    InitPSandMO();

    // Phase 1: Start secure
    MakeSecure_PS();
    DataModel::Nullable<GenericOverallCurrentState> readVal;
    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_EQ(readVal.Value().secureState.Value(), true);

    // Phase 2: Open the closure (authorized)
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::Success);
    MainStateEnum state;
    EXPECT_EQ(mLogic->GetMainState(state), CHIP_NO_ERROR);
    EXPECT_EQ(state, MainStateEnum::kMoving);

    // Phase 3: Movement completes — delegate updates state
    DataModel::Nullable<GenericOverallCurrentState> openState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyOpened)), NullOptional, NullOptional,
        DataModel::MakeNullable(false)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(openState), CHIP_NO_ERROR);
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);

    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_EQ(readVal.Value().secureState.Value(), false); // No longer secure

    // Phase 4: Close again (authorized)
    EXPECT_EQ(
        mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyClosed), NullOptional, NullOptional),
        Status::Success);

    // Phase 5: Movement completes — delegate updates to FullyClosed + Secure
    DataModel::Nullable<GenericOverallCurrentState> closedState(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional,
        DataModel::MakeNullable(true)));
    EXPECT_EQ(mLogic->SetOverallCurrentState(closedState), CHIP_NO_ERROR);
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);

    EXPECT_EQ(mLogic->GetOverallCurrentState(readVal), CHIP_NO_ERROR);
    EXPECT_EQ(readVal.Value().secureState.Value(), true);
    EXPECT_EQ(readVal.Value().position.Value().Value(), CurrentPositionEnum::kFullyClosed);
}

// E2E-11: Error state blocks commands, recovery after clear
TEST_F(TestClosureControlAttackSim, Attack_PROP031_ErrorState_BlocksAndRecovers)
{
    InitPSandMO();

    DataModel::Nullable<GenericOverallCurrentState> state(GenericOverallCurrentState(
        Optional(DataModel::MakeNullable(CurrentPositionEnum::kFullyClosed)), NullOptional, NullOptional));
    EXPECT_EQ(mLogic->SetOverallCurrentState(state), CHIP_NO_ERROR);

    // Simulate error
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kError), CHIP_NO_ERROR);

    // MoveTo blocked in Error state
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::InvalidInState);

    // Calibrate blocked in Error state
    // (Need calibration feature for this — skip if not present)

    // Recovery: transition back to Stopped
    EXPECT_EQ(mLogic->SetMainState(MainStateEnum::kStopped), CHIP_NO_ERROR);
    mLogic->ClearCurrentErrorList();

    // Now MoveTo works again
    EXPECT_EQ(mLogic->HandleMoveTo(Optional<TargetPositionEnum>(TargetPositionEnum::kMoveToFullyOpen), NullOptional, NullOptional),
              Status::Success);

    MainStateEnum readState;
    EXPECT_EQ(mLogic->GetMainState(readState), CHIP_NO_ERROR);
    EXPECT_EQ(readState, MainStateEnum::kMoving);
}

} // namespace
