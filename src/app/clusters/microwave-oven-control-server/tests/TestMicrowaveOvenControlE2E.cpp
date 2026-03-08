/*
 *    Copyright (c) 2025 Project CHIP Authors
 *    All rights reserved.
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
 */

/**
 * @file TestMicrowaveOvenControlE2E.cpp
 *
 * Real-server E2E attack-simulation tests for the Microwave Oven Control
 * cluster (§8.13).
 *
 * These tests instantiate REAL MicrowaveOvenControl::Instance,
 * OperationalState::Instance, and ModeBase::Instance objects and exercise
 * the SetCookingParameters and AddMoreTime command paths via InvokeCommand.
 *
 * Three VALID vulnerability claims are tested:
 *
 *   PROP_004 — SetCookingParameters "MAY respond" vs "SHALL respond"
 *              INVALID_IN_STATE.  The spec uses MAY (§8.13.6.1) allowing
 *              permissive implementations, but the SDK is strict: it rejects
 *              all non-Stopped states.  This is a spec gap.
 *
 *   PROP_005 — AddMoreTime has no operational-state restriction beyond
 *              Error.  The SDK allows AddMoreTime when Stopped or Paused,
 *              enabling CookTime manipulation when the oven is off.
 *
 *   PROP_028 — AddMoreTime has no rate limiting.  Rapid-fire calls all
 *              succeed without any throttling or cooldown mechanism.
 */

#include <gtest/gtest.h>

#include <app/clusters/microwave-oven-control-server/microwave-oven-control-server.h>
#include <app/clusters/operational-state-server/operational-state-server.h>
#include <app/clusters/operational-state-server/operational-state-cluster-objects.h>
#include <app/clusters/mode-base-server/mode-base-server.h>
#include <app/clusters/mode-base-server/mode-base-cluster-objects.h>
#include <app/CommandHandler.h>
#include <app/CommandHandlerInterface.h>
#include <app/ConcreteCommandPath.h>
#include <app/SafeAttributePersistenceProvider.h>
#include <app/data-model/Encode.h>
#include <app/util/mock/Functions.h>
#include <app/util/mock/MockNodeConfig.h>
#include <clusters/MicrowaveOvenControl/ClusterId.h>
#include <clusters/MicrowaveOvenControl/Commands.h>
#include <clusters/MicrowaveOvenMode/ClusterId.h>
#include <clusters/MicrowaveOvenMode/Enums.h>
#include <clusters/OperationalState/ClusterId.h>
#include <clusters/OperationalState/Enums.h>
#include <lib/core/TLV.h>
#include <lib/core/DataModelTypes.h>
#include <access/SubjectDescriptor.h>
#include <messaging/ExchangeContext.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::MicrowaveOvenControl;
using Status = Protocols::InteractionModel::Status;

// ===== Constants =====

static constexpr EndpointId kTestEndpoint     = 1;
static constexpr uint32_t kMaxCookTimeSec     = 65535u;
static constexpr uint8_t kModeNormal          = 0;
static constexpr uint8_t kModeDefrost         = 1;
static constexpr uint8_t kNumModes            = 2;

// ===== Mock OperationalState Delegate =====

class MockOpStateDelegate : public OperationalState::Delegate
{
public:
    DataModel::Nullable<uint32_t> GetCountdownTime() override { return DataModel::NullNullable; }

    CHIP_ERROR GetOperationalStateAtIndex(size_t index, OperationalState::GenericOperationalState & state) override
    {
        // Expose 4 standard operational states
        static const uint8_t kStates[] = {
            to_underlying(OperationalState::OperationalStateEnum::kStopped),
            to_underlying(OperationalState::OperationalStateEnum::kRunning),
            to_underlying(OperationalState::OperationalStateEnum::kPaused),
            to_underlying(OperationalState::OperationalStateEnum::kError),
        };
        if (index >= 4)
            return CHIP_ERROR_NOT_FOUND;
        state.Set(kStates[index]);
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR GetOperationalPhaseAtIndex(size_t index, MutableCharSpan & phase) override { return CHIP_ERROR_NOT_FOUND; }

    void HandlePauseStateCallback(OperationalState::GenericOperationalError & err) override
    {
        err.Set(to_underlying(OperationalState::ErrorStateEnum::kNoError));
    }
    void HandleResumeStateCallback(OperationalState::GenericOperationalError & err) override
    {
        err.Set(to_underlying(OperationalState::ErrorStateEnum::kNoError));
    }
    void HandleStartStateCallback(OperationalState::GenericOperationalError & err) override
    {
        err.Set(to_underlying(OperationalState::ErrorStateEnum::kNoError));
    }
    void HandleStopStateCallback(OperationalState::GenericOperationalError & err) override
    {
        err.Set(to_underlying(OperationalState::ErrorStateEnum::kNoError));
    }
};

// ===== Mock MicrowaveOvenMode Delegate =====

class MockMicrowaveOvenModeDelegate : public ModeBase::Delegate
{
    using ModeTagStructType = chip::app::Clusters::detail::Structs::ModeTagStruct::Type;

    ModeTagStructType mTagsNormal[1]  = { { .value = to_underlying(MicrowaveOvenMode::ModeTag::kNormal) } };
    ModeTagStructType mTagsDefrost[1] = { { .value = to_underlying(MicrowaveOvenMode::ModeTag::kDefrost) } };

    const chip::app::Clusters::detail::Structs::ModeOptionStruct::Type kModes[kNumModes] = {
        { .label = CharSpan::fromCharString("Normal"),  .mode = kModeNormal,  .modeTags = DataModel::List<const ModeTagStructType>(mTagsNormal) },
        { .label = CharSpan::fromCharString("Defrost"), .mode = kModeDefrost, .modeTags = DataModel::List<const ModeTagStructType>(mTagsDefrost) },
    };

public:
    CHIP_ERROR Init() override { return CHIP_NO_ERROR; }

    void HandleChangeToMode(uint8_t NewMode, ModeBase::Commands::ChangeToModeResponse::Type & response) override
    {
        response.status = to_underlying(ModeBase::StatusCode::kSuccess);
    }

    CHIP_ERROR GetModeLabelByIndex(uint8_t modeIndex, MutableCharSpan & label) override
    {
        if (modeIndex >= kNumModes)
            return CHIP_ERROR_PROVIDER_LIST_EXHAUSTED;
        return CopyCharSpanToMutableCharSpan(kModes[modeIndex].label, label);
    }

    CHIP_ERROR GetModeValueByIndex(uint8_t modeIndex, uint8_t & value) override
    {
        if (modeIndex >= kNumModes)
            return CHIP_ERROR_PROVIDER_LIST_EXHAUSTED;
        value = kModes[modeIndex].mode;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR GetModeTagsByIndex(uint8_t modeIndex,
                                  DataModel::List<chip::app::Clusters::detail::Structs::ModeTagStruct::Type> & tags) override
    {
        if (modeIndex >= kNumModes)
            return CHIP_ERROR_PROVIDER_LIST_EXHAUSTED;
        if (tags.size() < kModes[modeIndex].modeTags.size())
            return CHIP_ERROR_INVALID_ARGUMENT;
        std::copy(kModes[modeIndex].modeTags.begin(), kModes[modeIndex].modeTags.end(), tags.begin());
        tags.reduce_size(kModes[modeIndex].modeTags.size());
        return CHIP_NO_ERROR;
    }
};

// ===== Mock MicrowaveOvenControl Delegate =====

class MockMicrowaveOvenControlDelegate : public MicrowaveOvenControl::Delegate
{
    uint8_t mPowerSettingNum  = kDefaultMaxPowerNum;
    uint32_t mMaxCookTimeSec  = kMaxCookTimeSec;
    uint8_t mCallbackCount    = 0;
    MicrowaveOvenControl::Instance * mControlInstance = nullptr;

public:
    void SetControlInstance(MicrowaveOvenControl::Instance * inst) { mControlInstance = inst; }

    Protocols::InteractionModel::Status HandleSetCookingParametersCallback(uint8_t cookMode, uint32_t cookTimeSec,
                                                                           bool startAfterSetting,
                                                                           Optional<uint8_t> powerSettingNum,
                                                                           Optional<uint8_t> wattSettingIndex) override
    {
        mCallbackCount++;
        if (mControlInstance)
        {
            mControlInstance->SetCookTimeSec(cookTimeSec);
        }
        if (powerSettingNum.HasValue())
        {
            mPowerSettingNum = powerSettingNum.Value();
        }
        return Status::Success;
    }

    Protocols::InteractionModel::Status HandleModifyCookTimeSecondsCallback(uint32_t finalCookTimeSec) override
    {
        mCallbackCount++;
        if (mControlInstance)
        {
            mControlInstance->SetCookTimeSec(finalCookTimeSec);
        }
        return Status::Success;
    }

    CHIP_ERROR GetWattSettingByIndex(uint8_t index, uint16_t & wattSetting) override { return CHIP_ERROR_NOT_FOUND; }

    uint32_t GetMaxCookTimeSec() const override { return mMaxCookTimeSec; }
    uint8_t GetPowerSettingNum() const override { return mPowerSettingNum; }
    uint8_t GetMinPowerNum() const override { return kDefaultMinPowerNum; }
    uint8_t GetMaxPowerNum() const override { return kDefaultMaxPowerNum; }
    uint8_t GetPowerStepNum() const override { return kDefaultPowerStepNum; }
    uint8_t GetCurrentWattIndex() const override { return 0; }
    uint16_t GetWattRating() const override { return 0; }

    uint8_t GetCallbackCount() const { return mCallbackCount; }
    void ResetCallbackCount() { mCallbackCount = 0; }
};

// ===== Mock CommandHandler =====

class MockCommandHandler : public CommandHandler
{
public:
    Status lastStatus = Status::Failure;

    CHIP_ERROR FallibleAddStatus(const ConcreteCommandPath & aRequestCommandPath,
                                 const Protocols::InteractionModel::ClusterStatusCode & aStatus,
                                 const char * context = nullptr) override
    {
        lastStatus = aStatus.GetStatus();
        return CHIP_NO_ERROR;
    }

    void AddStatus(const ConcreteCommandPath & aRequestCommandPath,
                   const Protocols::InteractionModel::ClusterStatusCode & aStatus,
                   const char * context = nullptr) override
    {
        lastStatus = aStatus.GetStatus();
    }

    FabricIndex GetAccessingFabricIndex() const override { return 1; }

    CHIP_ERROR AddResponseData(const ConcreteCommandPath & aRequestCommandPath, CommandId aResponseCommandId,
                               const DataModel::EncodableToTLV & aEncodable) override
    {
        return CHIP_NO_ERROR;
    }

    void AddResponse(const ConcreteCommandPath & aRequestCommandPath, CommandId aResponseCommandId,
                     const DataModel::EncodableToTLV & aEncodable) override
    {
    }

    bool IsTimedInvoke() const override { return false; }

    void FlushAcksRightAwayOnSlowCommand() override {}

    Access::SubjectDescriptor GetSubjectDescriptor() const override
    {
        return Access::SubjectDescriptor{
            .fabricIndex = 1,
            .authMode    = Access::AuthMode::kCase,
            .subject     = 0x1234,
        };
    }

    Messaging::ExchangeContext * GetExchangeContext() const override { return nullptr; }
};

// ===== Minimal SafeAttributePersistenceProvider =====

class TestPersistenceProvider : public SafeAttributePersistenceProvider
{
public:
    CHIP_ERROR SafeWriteValue(const ConcreteAttributePath & aPath, const ByteSpan & aValue) override { return CHIP_NO_ERROR; }
    CHIP_ERROR SafeReadValue(const ConcreteAttributePath & aPath, MutableByteSpan & aValue) override
    {
        return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
    }
};

// ===== TLV Encode Helpers =====

static void EncodeSetCookingParameters(const MicrowaveOvenControl::Commands::SetCookingParameters::Type & cmd,
                                       uint8_t * buffer, size_t bufSize, TLV::TLVReader & reader)
{
    TLV::TLVWriter writer;
    writer.Init(buffer, bufSize);
    ASSERT_EQ(cmd.Encode(writer, TLV::AnonymousTag()), CHIP_NO_ERROR);
    reader.Init(buffer, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
}

static void EncodeAddMoreTime(const MicrowaveOvenControl::Commands::AddMoreTime::Type & cmd,
                              uint8_t * buffer, size_t bufSize, TLV::TLVReader & reader)
{
    TLV::TLVWriter writer;
    writer.Init(buffer, bufSize);
    ASSERT_EQ(cmd.Encode(writer, TLV::AnonymousTag()), CHIP_NO_ERROR);
    reader.Init(buffer, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
}

// ===== Test Fixture =====

class TestMicrowaveOvenControlE2E : public ::testing::Test
{
protected:
    MockOpStateDelegate mOpStateDelegate;
    MockMicrowaveOvenModeDelegate mModeDelegate;
    MockMicrowaveOvenControlDelegate mControlDelegate;
    TestPersistenceProvider mPersistence;

    OperationalState::Instance * mOpStateInstance     = nullptr;
    ModeBase::Instance * mModeInstance                = nullptr;
    MicrowaveOvenControl::Instance * mControlInstance = nullptr;

    void SetUp() override
    {
        SetSafeAttributePersistenceProvider(&mPersistence);

        // Configure mock ember with all 3 clusters on the test endpoint
        static const chip::Test::MockClusterConfig mwocCluster(MicrowaveOvenControl::Id);
        static const chip::Test::MockClusterConfig opStateCluster(OperationalState::Id);
        static const chip::Test::MockClusterConfig mwomCluster(MicrowaveOvenMode::Id);
        static const chip::Test::MockEndpointConfig endpoint(kTestEndpoint, { mwocCluster, opStateCluster, mwomCluster });
        static const chip::Test::MockNodeConfig node({ endpoint });
        chip::Test::SetMockNodeConfig(node);

        // 1. Create OperationalState instance (must be first — no deps)
        mOpStateInstance = new OperationalState::Instance(&mOpStateDelegate, kTestEndpoint);
        ASSERT_EQ(mOpStateInstance->Init(), CHIP_NO_ERROR);

        // 2. Create MicrowaveOvenMode instance (ModeBase) — no deps besides mock ember
        mModeInstance = new ModeBase::Instance(&mModeDelegate, kTestEndpoint, MicrowaveOvenMode::Id, 0 /* features */);
        ASSERT_EQ(mModeInstance->Init(), CHIP_NO_ERROR);

        // 3. Create MicrowaveOvenControl instance — depends on both above
        mControlInstance = new MicrowaveOvenControl::Instance(
            &mControlDelegate, kTestEndpoint, MicrowaveOvenControl::Id,
            BitMask<MicrowaveOvenControl::Feature>(MicrowaveOvenControl::Feature::kPowerAsNumber),
            *mOpStateInstance, *mModeInstance);
        ASSERT_EQ(mControlInstance->Init(), CHIP_NO_ERROR);

        // Wire the delegate back to the Instance so callbacks update CookTimeSec
        mControlDelegate.SetControlInstance(mControlInstance);
    }

    void TearDown() override
    {
        delete mControlInstance;
        mControlInstance = nullptr;

        if (mModeInstance)
        {
            mModeInstance->Shutdown();
            delete mModeInstance;
            mModeInstance = nullptr;
        }

        delete mOpStateInstance;
        mOpStateInstance = nullptr;

        chip::Test::ResetMockNodeConfig();
    }

    // Helper: set operational state (Stopped, Running, Paused)
    void SetOperationalState(OperationalState::OperationalStateEnum state)
    {
        if (state == OperationalState::OperationalStateEnum::kError)
        {
            OperationalState::Structs::ErrorStateStruct::Type err;
            err.errorStateID = to_underlying(OperationalState::ErrorStateEnum::kUnableToCompleteOperation);
            mOpStateInstance->OnOperationalErrorDetected(err);
        }
        else
        {
            ASSERT_EQ(mOpStateInstance->SetOperationalState(to_underlying(state)), CHIP_NO_ERROR);
        }
    }

    // Helper: invoke SetCookingParameters on the real Instance
    Status InvokeSetCookingParameters(Optional<uint8_t> cookMode = NullOptional,
                                      Optional<uint32_t> cookTime = Optional<uint32_t>(60),
                                      Optional<uint8_t> powerSetting = NullOptional)
    {
        MockCommandHandler handler;
        uint8_t tlvBuffer[128];
        TLV::TLVReader reader;

        MicrowaveOvenControl::Commands::SetCookingParameters::Type cmd;
        cmd.cookMode     = cookMode;
        cmd.cookTime     = cookTime;
        cmd.powerSetting = powerSetting;

        EncodeSetCookingParameters(cmd, tlvBuffer, sizeof(tlvBuffer), reader);

        ConcreteCommandPath path(kTestEndpoint, MicrowaveOvenControl::Id,
                                 MicrowaveOvenControl::Commands::SetCookingParameters::Id);
        CommandHandlerInterface::HandlerContext ctx(handler, path, reader);
        static_cast<CommandHandlerInterface *>(mControlInstance)->InvokeCommand(ctx);

        return handler.lastStatus;
    }

    // Helper: invoke AddMoreTime on the real Instance
    Status InvokeAddMoreTime(uint32_t timeToAdd)
    {
        MockCommandHandler handler;
        uint8_t tlvBuffer[64];
        TLV::TLVReader reader;

        MicrowaveOvenControl::Commands::AddMoreTime::Type cmd;
        cmd.timeToAdd = timeToAdd;

        EncodeAddMoreTime(cmd, tlvBuffer, sizeof(tlvBuffer), reader);

        ConcreteCommandPath path(kTestEndpoint, MicrowaveOvenControl::Id,
                                 MicrowaveOvenControl::Commands::AddMoreTime::Id);
        CommandHandlerInterface::HandlerContext ctx(handler, path, reader);
        static_cast<CommandHandlerInterface *>(mControlInstance)->InvokeCommand(ctx);

        return handler.lastStatus;
    }
};

// ==========================================================================
// PROP_004: SetCookingParameters State Check (Spec Gap: MAY vs SHALL)
//
// The spec §8.13.6.1 says the server "MAY respond with INVALID_IN_STATE"
// for SetCookingParameters, while §8.13.6.2.6 uses "SHALL respond" for
// AddMoreTime.  The SDK resolves this ambiguity with strict enforcement:
// SetCookingParameters is only allowed when Stopped.
// ==========================================================================

TEST_F(TestMicrowaveOvenControlE2E, PROP004_SetCookingParameters_Stopped_Succeeds)
{
    // Default state is Stopped
    EXPECT_EQ(mOpStateInstance->GetCurrentOperationalState(),
              to_underlying(OperationalState::OperationalStateEnum::kStopped));

    Status status = InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(60));
    EXPECT_EQ(status, Status::Success)
        << "SetCookingParameters should succeed when Stopped";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP004_SetCookingParameters_Running_Rejected)
{
    SetOperationalState(OperationalState::OperationalStateEnum::kRunning);

    Status status = InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(60));
    EXPECT_EQ(status, Status::InvalidInState)
        << "PROP_004: SDK returns INVALID_IN_STATE when Running (spec says MAY — SDK is strict)";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP004_SetCookingParameters_Paused_Rejected)
{
    SetOperationalState(OperationalState::OperationalStateEnum::kPaused);

    Status status = InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(60));
    EXPECT_EQ(status, Status::InvalidInState)
        << "PROP_004: SDK returns INVALID_IN_STATE when Paused (spec says MAY — SDK is strict)";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP004_SetCookingParameters_Error_Rejected)
{
    SetOperationalState(OperationalState::OperationalStateEnum::kError);

    Status status = InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(60));
    EXPECT_EQ(status, Status::InvalidInState)
        << "PROP_004: SDK returns INVALID_IN_STATE when Error (spec says MAY — SDK is strict)";
}

// ==========================================================================
// PROP_005: AddMoreTime Has No Operational State Restriction Beyond Error
//
// The SDK only blocks AddMoreTime when operational state == Error.
// It allows AddMoreTime in Stopped and Paused states, enabling CookTime
// manipulation when the oven is not actively cooking.
// ==========================================================================

TEST_F(TestMicrowaveOvenControlE2E, PROP005_AddMoreTime_Running_Succeeds)
{
    // First set a low cook time so we have room to add
    SetOperationalState(OperationalState::OperationalStateEnum::kStopped);
    InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(100));

    SetOperationalState(OperationalState::OperationalStateEnum::kRunning);

    Status status = InvokeAddMoreTime(50);
    EXPECT_EQ(status, Status::Success)
        << "AddMoreTime should succeed when Running (normal use case)";
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), 150u)
        << "CookTime should increase by timeToAdd";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP005_AddMoreTime_Stopped_Succeeds_Vulnerability)
{
    // CookTime starts at default 30s
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), kDefaultCookTimeSec);

    // Oven is Stopped — not cooking
    EXPECT_EQ(mOpStateInstance->GetCurrentOperationalState(),
              to_underlying(OperationalState::OperationalStateEnum::kStopped));

    // Attack: manipulate CookTime while oven is off
    Status status = InvokeAddMoreTime(100);
    EXPECT_EQ(status, Status::Success)
        << "PROP_005: AddMoreTime succeeds in Stopped state — CookTime manipulable when oven is off";
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), 130u)
        << "CookTime changed from 30 to 130 while oven was Stopped";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP005_AddMoreTime_Paused_Succeeds_Vulnerability)
{
    // Set cook time and move to Paused state
    SetOperationalState(OperationalState::OperationalStateEnum::kStopped);
    InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(100));

    SetOperationalState(OperationalState::OperationalStateEnum::kPaused);

    Status status = InvokeAddMoreTime(200);
    EXPECT_EQ(status, Status::Success)
        << "PROP_005: AddMoreTime succeeds in Paused state — no restriction beyond Error";
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), 300u)
        << "CookTime extended while oven was Paused";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP005_AddMoreTime_Error_Rejected)
{
    SetOperationalState(OperationalState::OperationalStateEnum::kError);

    Status status = InvokeAddMoreTime(10);
    EXPECT_EQ(status, Status::InvalidInState)
        << "AddMoreTime correctly blocks when in Error state (only restriction)";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP005_AddMoreTime_Stopped_MaximizeCookTime)
{
    // Start from default cook time, oven is Stopped
    uint32_t currentCookTime = mControlInstance->GetCookTimeSec();
    uint32_t addAmount       = kMaxCookTimeSec - currentCookTime;

    // Maximize cook time while oven is off
    Status status = InvokeAddMoreTime(addAmount);
    EXPECT_EQ(status, Status::Success)
        << "PROP_005: Can maximize CookTime while Stopped";
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), kMaxCookTimeSec)
        << "CookTime maximized to " << kMaxCookTimeSec << " while oven was Stopped";
}

// ==========================================================================
// PROP_028: AddMoreTime Has No Rate Limiting
//
// The SDK imposes no rate-limiting, cooldown, or frequency restriction on
// AddMoreTime.  Rapid successive calls all succeed until the MaxCookTime
// ceiling is reached.
// ==========================================================================

TEST_F(TestMicrowaveOvenControlE2E, PROP028_RapidAddMoreTime_NoThrottling)
{
    // Set initial cook time to a low value
    SetOperationalState(OperationalState::OperationalStateEnum::kStopped);
    InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(kMinCookTimeSec));

    SetOperationalState(OperationalState::OperationalStateEnum::kRunning);

    mControlDelegate.ResetCallbackCount();

    // Rapid-fire 10 AddMoreTime calls — no throttling, no cooldown
    const uint32_t kSmallIncrement = 10;
    uint32_t expectedCookTime      = kMinCookTimeSec;

    for (int i = 0; i < 10; i++)
    {
        Status status = InvokeAddMoreTime(kSmallIncrement);
        EXPECT_EQ(status, Status::Success)
            << "PROP_028: AddMoreTime call #" << (i + 1) << " should succeed (no rate limit)";
        expectedCookTime += kSmallIncrement;
        EXPECT_EQ(mControlInstance->GetCookTimeSec(), expectedCookTime)
            << "CookTime should accumulate after each call";
    }

    // All 10 calls succeeded without any rate limiting
    EXPECT_EQ(mControlDelegate.GetCallbackCount(), 10u)
        << "PROP_028: All 10 rapid-fire calls invoked the delegate — no throttling";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP028_RapidAddMoreTime_CeilingReached)
{
    // Start at low cook time
    SetOperationalState(OperationalState::OperationalStateEnum::kStopped);
    InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(100));

    SetOperationalState(OperationalState::OperationalStateEnum::kRunning);

    // Add large amount that brings us just below ceiling
    Status status = InvokeAddMoreTime(kMaxCookTimeSec - 101);
    EXPECT_EQ(status, Status::Success)
        << "AddMoreTime to near-ceiling succeeds";
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), kMaxCookTimeSec - 1);

    // Add 1 more — exactly at ceiling
    status = InvokeAddMoreTime(1);
    EXPECT_EQ(status, Status::Success)
        << "AddMoreTime hitting exactly MaxCookTime succeeds";
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), kMaxCookTimeSec);

    // Any further addition exceeds ceiling → ConstraintError
    status = InvokeAddMoreTime(1);
    EXPECT_EQ(status, Status::ConstraintError)
        << "AddMoreTime exceeding MaxCookTime returns ConstraintError";
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), kMaxCookTimeSec)
        << "CookTime unchanged after ceiling-exceeding call";
}

TEST_F(TestMicrowaveOvenControlE2E, PROP028_BurstInStopped_NoRateLimit)
{
    // Even in Stopped state (PROP_005 + PROP_028 combined attack)
    mControlDelegate.ResetCallbackCount();
    uint32_t expected = mControlInstance->GetCookTimeSec(); // default 30

    for (int i = 0; i < 20; i++)
    {
        Status status = InvokeAddMoreTime(1);
        EXPECT_EQ(status, Status::Success)
            << "PROP_005+028: Burst call #" << (i + 1) << " in Stopped state succeeds";
        expected += 1;
    }

    EXPECT_EQ(mControlInstance->GetCookTimeSec(), expected)
        << "CookTime accumulated via 20 burst calls while Stopped";
    EXPECT_EQ(mControlDelegate.GetCallbackCount(), 20u)
        << "All 20 calls dispatched — no frequency limiting whatsoever";
}

// ==========================================================================
// Cross-cutting validation: Confirm basic correctness of the test setup
// ==========================================================================

TEST_F(TestMicrowaveOvenControlE2E, SetCookingParameters_ValidCookTime)
{
    Status status = InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(120));
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(mControlInstance->GetCookTimeSec(), 120u);
}

TEST_F(TestMicrowaveOvenControlE2E, SetCookingParameters_CookTimeExceedsMax_ConstraintError)
{
    Status status = InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(kMaxCookTimeSec + 1));
    EXPECT_EQ(status, Status::ConstraintError)
        << "CookTime exceeding MaxCookTime should return ConstraintError";
}

TEST_F(TestMicrowaveOvenControlE2E, SetCookingParameters_CookTimeZero_ConstraintError)
{
    Status status = InvokeSetCookingParameters(NullOptional, Optional<uint32_t>(0));
    EXPECT_EQ(status, Status::ConstraintError)
        << "CookTime of 0 should return ConstraintError (min is 1)";
}

TEST_F(TestMicrowaveOvenControlE2E, AddMoreTime_ExceedsMax_ConstraintError)
{
    // Default cook time is 30, try to add way too much
    Status status = InvokeAddMoreTime(kMaxCookTimeSec + 1);
    EXPECT_EQ(status, Status::ConstraintError)
        << "AddMoreTime exceeding MaxCookTime should return ConstraintError";
}
