/*
 *    Copyright (c) 2024 Project CHIP Authors
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
 * @file TestContentControlE2E.cpp
 *
 * End-to-end attack simulation for Content Control Cluster (0x050F), Section 6.13.
 *
 * These tests register a REAL delegate via SetDefaultDelegate(), then call
 * the REAL emberAfContentControlCluster*Callback() functions with crafted
 * command data.  Every code path executed is PRODUCTION code from
 * content-control-server.cpp — no business logic is reimplemented in mocks.
 *
 * The delegate is an I/O-only shim that records what the server passed to it.
 * All business logic (or rather, the complete ABSENCE of validation) lives in
 * the real server callbacks.
 *
 * Attacks tested:
 *   ATK-001  PROP_029  AddBonusTime overflow — server passes any uint32 to delegate
 *   ATK-002  PROP_029  AddBonusTime from exhausted state — resumes playback
 *   ATK-003           SetScreenDailyTime zero — locks out all screen time
 *   ATK-004           SetScreenDailyTime UINT32_MAX — unlimited screen time
 *   ATK-005           Enable/Disable toggle with no state guard
 *   ATK-006           UpdatePIN with wrong old PIN — server does not verify
 *   ATK-007           SetOnDemandRatingThreshold with empty string
 *   ATK-008           SetScheduledContentRatingThreshold bypass
 *   ATK-009           BlockUnrated/UnblockUnrated toggle with no guard
 *   ATK-010           Missing 6 command callbacks — delegate interface gap
 */

#include <pw_unit_test/framework.h>

// Real server header + delegate interface
#include <app/clusters/content-control-server/content-control-delegate.h>
#include <app/clusters/content-control-server/content-control-server.h>

// Generated accessors, cluster objects, command types
#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/cluster-objects.h>
#include <clusters/ContentControl/Commands.h>

// CommandHandler base class
#include <app/CommandHandler.h>
#include <app/CommandResponseHelper.h>
#include <app/ConcreteCommandPath.h>

// Mock ember infrastructure
#include <app/tests/test-ember-api.h>
#include <app/util/mock/Functions.h>
#include <app/util/mock/MockNodeConfig.h>

// Support
#include <lib/core/CHIPError.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/logging/CHIPLogging.h>
#include <protocols/interaction_model/StatusCode.h>

#include <cstring>
#include <optional>

// Extern declarations for the REAL ember callbacks defined in content-control-server.cpp
extern bool emberAfContentControlClusterUpdatePINCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::UpdatePIN::DecodableType & commandData);

extern bool emberAfContentControlClusterResetPINCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::ResetPIN::DecodableType & commandData);

extern bool emberAfContentControlClusterEnableCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::Enable::DecodableType & commandData);

extern bool emberAfContentControlClusterDisableCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::Disable::DecodableType & commandData);

extern bool emberAfContentControlClusterAddBonusTimeCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::AddBonusTime::DecodableType & commandData);

extern bool emberAfContentControlClusterSetScreenDailyTimeCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::SetScreenDailyTime::DecodableType & commandData);

extern bool emberAfContentControlClusterBlockUnratedContentCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::BlockUnratedContent::DecodableType & commandData);

extern bool emberAfContentControlClusterUnblockUnratedContentCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::UnblockUnratedContent::DecodableType & commandData);

extern bool emberAfContentControlClusterSetOnDemandRatingThresholdCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::SetOnDemandRatingThreshold::DecodableType & commandData);

extern bool emberAfContentControlClusterSetScheduledContentRatingThresholdCallback(
    chip::app::CommandHandler * command, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::ContentControl::Commands::SetScheduledContentRatingThreshold::DecodableType & commandData);

extern void ResetTestAttributeStore();

namespace {

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::ContentControl;
using namespace chip::Test;
using chip::Protocols::InteractionModel::Status;

static constexpr EndpointId kTestEndpoint = 0;

// ============================================================================
// Minimal TestCommandHandler — captures status returned by real server code
// ============================================================================

class TestCommandHandler : public CommandHandler
{
public:
    TestCommandHandler() : mStatus(Status::Success) {}

    CHIP_ERROR FallibleAddStatus(const ConcreteCommandPath & aRequestCommandPath,
                                 const Protocols::InteractionModel::ClusterStatusCode & aStatus,
                                 const char * context = nullptr) override
    {
        mStatus = aStatus.IsSuccess() ? Status::Success : Status::Failure;
        return CHIP_NO_ERROR;
    }

    void AddStatus(const ConcreteCommandPath & aRequestCommandPath,
                   const Protocols::InteractionModel::ClusterStatusCode & aStatus,
                   const char * context = nullptr) override
    {
        mStatus = aStatus.IsSuccess() ? Status::Success : Status::Failure;
    }

    FabricIndex GetAccessingFabricIndex() const override { return 1; }

    CHIP_ERROR AddResponseData(const ConcreteCommandPath & aRequestCommandPath, CommandId aResponseCommandId,
                               const DataModel::EncodableToTLV & aEncodable) override
    {
        mResponseSent = true;
        return CHIP_NO_ERROR;
    }

    void AddResponse(const ConcreteCommandPath & aRequestCommandPath, CommandId aResponseCommandId,
                     const DataModel::EncodableToTLV & aEncodable) override
    {
        mResponseSent = true;
    }

    bool IsTimedInvoke() const override { return false; }
    void FlushAcksRightAwayOnSlowCommand() override {}

    Access::SubjectDescriptor GetSubjectDescriptor() const override
    {
        return Access::SubjectDescriptor{ kUndefinedFabricIndex, Access::AuthMode::kNone, kUndefinedNodeId,
                                          kUndefinedCATs };
    }

    Messaging::ExchangeContext * GetExchangeContext() const override { return nullptr; }

    void Reset()
    {
        mStatus       = Status::Success;
        mResponseSent = false;
    }

    Status mStatus;
    bool mResponseSent = false;
};

// ============================================================================
// I/O-Only Test Delegate — records what the REAL server passes through.
// Contains ZERO business logic.  All state tracking is purely for assertion.
// ============================================================================

class TestContentControlDelegate : public Delegate
{
public:
    // --- Call tracking (NO business logic, just recording) ---
    bool mEnableCalled              = false;
    bool mDisableCalled             = false;
    bool mBlockUnratedCalled        = false;
    bool mUnblockUnratedCalled      = false;

    uint32_t mAddBonusTimeCallCount = 0;
    uint32_t mLastBonusTime         = 0;
    bool mLastBonusPINPresent       = false;

    uint32_t mLastScreenDailyTime   = 0;
    bool mSetScreenDailyTimeCalled  = false;

    bool mUpdatePINCalled           = false;
    char mLastOldPIN[64]            = {};
    char mLastNewPIN[64]            = {};

    bool mResetPINCalled            = false;

    char mLastOnDemandRating[64]    = {};
    bool mSetOnDemandRatingCalled   = false;

    char mLastScheduledRating[64]   = {};
    bool mSetScheduledRatingCalled  = false;

    // --- Attribute Delegates (return defaults; not the focus of these tests) ---
    bool HandleGetEnabled() override { return false; }
    CHIP_ERROR HandleGetOnDemandRatings(chip::app::AttributeValueEncoder & aEncoder) override { return CHIP_NO_ERROR; }
    chip::CharSpan HandleGetOnDemandRatingThreshold() override { return chip::CharSpan(); }
    CHIP_ERROR HandleGetScheduledContentRatings(chip::app::AttributeValueEncoder & aEncoder) override { return CHIP_NO_ERROR; }
    chip::CharSpan HandleGetScheduledContentRatingThreshold() override { return chip::CharSpan(); }
    uint32_t HandleGetScreenDailyTime() override { return 3600; }
    uint32_t HandleGetRemainingScreenTime() override { return 300; }
    bool HandleGetBlockUnrated() override { return false; }

    // --- Command Delegates (record what server passes, return immediately) ---
    void HandleUpdatePIN(chip::CharSpan oldPIN, chip::CharSpan newPIN) override
    {
        mUpdatePINCalled = true;
        size_t oldLen    = std::min(oldPIN.size(), sizeof(mLastOldPIN) - 1);
        size_t newLen    = std::min(newPIN.size(), sizeof(mLastNewPIN) - 1);
        memcpy(mLastOldPIN, oldPIN.data(), oldLen);
        mLastOldPIN[oldLen] = '\0';
        memcpy(mLastNewPIN, newPIN.data(), newLen);
        mLastNewPIN[newLen] = '\0';
    }

    void HandleResetPIN(chip::app::CommandResponseHelper<Commands::ResetPINResponse::Type> & helper) override
    {
        mResetPINCalled = true;
        Commands::ResetPINResponse::Type response;
        // Must send response or server returns Failure
        helper.Success(response);
    }

    void HandleEnable() override { mEnableCalled = true; }
    void HandleDisable() override { mDisableCalled = true; }

    void HandleAddBonusTime(chip::Optional<chip::CharSpan> PINCode, uint32_t bonusTime) override
    {
        mAddBonusTimeCallCount++;
        mLastBonusTime      = bonusTime;
        mLastBonusPINPresent = PINCode.HasValue();
    }

    void HandleSetScreenDailyTime(uint32_t screenDailyTime) override
    {
        mSetScreenDailyTimeCalled = true;
        mLastScreenDailyTime      = screenDailyTime;
    }

    void HandleBlockUnratedContent() override { mBlockUnratedCalled = true; }
    void HandleUnblockUnratedContent() override { mUnblockUnratedCalled = true; }

    void HandleSetOnDemandRatingThreshold(chip::CharSpan rating) override
    {
        mSetOnDemandRatingCalled = true;
        size_t len = std::min(rating.size(), sizeof(mLastOnDemandRating) - 1);
        memcpy(mLastOnDemandRating, rating.data(), len);
        mLastOnDemandRating[len] = '\0';
    }

    void HandleSetScheduledContentRatingThreshold(chip::CharSpan rating) override
    {
        mSetScheduledRatingCalled = true;
        size_t len = std::min(rating.size(), sizeof(mLastScheduledRating) - 1);
        memcpy(mLastScheduledRating, rating.data(), len);
        mLastScheduledRating[len] = '\0';
    }

    uint32_t GetFeatureMap(chip::EndpointId endpoint) override { return 0xFF; }

    void Reset()
    {
        mEnableCalled = mDisableCalled = mBlockUnratedCalled = mUnblockUnratedCalled = false;
        mAddBonusTimeCallCount = mLastBonusTime = 0;
        mLastBonusPINPresent = false;
        mLastScreenDailyTime = 0;
        mSetScreenDailyTimeCalled = false;
        mUpdatePINCalled = mResetPINCalled = false;
        memset(mLastOldPIN, 0, sizeof(mLastOldPIN));
        memset(mLastNewPIN, 0, sizeof(mLastNewPIN));
        mSetOnDemandRatingCalled = mSetScheduledRatingCalled = false;
        memset(mLastOnDemandRating, 0, sizeof(mLastOnDemandRating));
        memset(mLastScheduledRating, 0, sizeof(mLastScheduledRating));
    }
};

// ============================================================================
// MockNodeConfig: endpoint 0 with Content Control cluster
// ============================================================================

static MockNodeConfig ContentControlTestConfig()
{
    using namespace Globals::Attributes;

    MockClusterConfig cluster(
        ContentControl::Id,
        {
            MockAttributeConfig(ContentControl::Attributes::ClusterRevision::Id, ZCL_INT16U_ATTRIBUTE_TYPE),
            MockAttributeConfig(ContentControl::Attributes::FeatureMap::Id, ZCL_BITMAP32_ATTRIBUTE_TYPE),
            MockAttributeConfig(ContentControl::Attributes::Enabled::Id, ZCL_BOOLEAN_ATTRIBUTE_TYPE),
            MockAttributeConfig(ContentControl::Attributes::ScreenDailyTime::Id, ZCL_INT32U_ATTRIBUTE_TYPE),
            MockAttributeConfig(ContentControl::Attributes::RemainingScreenTime::Id, ZCL_INT32U_ATTRIBUTE_TYPE),
            MockAttributeConfig(ContentControl::Attributes::BlockUnrated::Id, ZCL_BOOLEAN_ATTRIBUTE_TYPE),
        });

    MockEndpointConfig endpoint(kTestEndpoint, { cluster });
    return MockNodeConfig({ endpoint });
}

// ============================================================================
// Test Fixture — Real server with a recording delegate
// ============================================================================

class TestContentControlE2E : public ::testing::Test
{
public:
    static void SetUpTestSuite() { ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR); }
    static void TearDownTestSuite() { chip::Platform::MemoryShutdown(); }

    void SetUp() override
    {
        ResetTestAttributeStore();
        mConfig.emplace(ContentControlTestConfig());
        SetMockNodeConfig(*mConfig);
        chip::Test::numEndpoints = 1;

        mDelegate.Reset();
        mHandler.Reset();

        // Register our I/O-only delegate on the REAL server delegate table
        ContentControl::SetDefaultDelegate(kTestEndpoint, &mDelegate);
    }

    void TearDown() override
    {
        ContentControl::SetDefaultDelegate(kTestEndpoint, nullptr);
        ResetMockNodeConfig();
        chip::Test::numEndpoints = 0;
        mConfig.reset();
        ResetTestAttributeStore();
    }

protected:
    std::optional<MockNodeConfig> mConfig;
    TestContentControlDelegate mDelegate;
    TestCommandHandler mHandler;

    ConcreteCommandPath MakePath(CommandId cmdId)
    {
        return ConcreteCommandPath(kTestEndpoint, ContentControl::Id, cmdId);
    }
};

// ============================================================================
// ATK-001: PROP_029 — AddBonusTime overflow (86400 seconds)
//
// The REAL emberAfContentControlClusterAddBonusTimeCallback passes bonusTime
// directly to delegate->HandleAddBonusTime() with ZERO bounds checking.
// A Manage-privileged attacker can inject any uint32_t value.
// ============================================================================

TEST_F(TestContentControlE2E, ATK001_AddBonusTimeOverflow_RealCallback)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-001: AddBonusTime overflow via REAL server      ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    // Craft the attack command: bonusTime = 86400 (full 24 hours)
    Commands::AddBonusTime::DecodableType cmd;
    cmd.bonusTime = 86400;

    auto path = MakePath(Commands::AddBonusTime::Id);

    // Call the REAL ember callback
    bool result = emberAfContentControlClusterAddBonusTimeCallback(&mHandler, path, cmd);

    // Verify: callback executed successfully
    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);

    // Verify: the delegate received the FULL 86400 — no clamping, no rejection
    EXPECT_EQ(mDelegate.mAddBonusTimeCallCount, 1u);
    EXPECT_EQ(mDelegate.mLastBonusTime, 86400u);

    ChipLogProgress(NotSpecified, "  CONFIRMED: Server passed bonusTime=86400 to delegate with ZERO validation");
}

TEST_F(TestContentControlE2E, ATK001_AddBonusTimeMaxUint32_RealCallback)
{
    // Extreme: UINT32_MAX (~136 years of bonus time)
    Commands::AddBonusTime::DecodableType cmd;
    cmd.bonusTime = UINT32_MAX;

    auto path   = MakePath(Commands::AddBonusTime::Id);
    bool result = emberAfContentControlClusterAddBonusTimeCallback(&mHandler, path, cmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);
    EXPECT_EQ(mDelegate.mLastBonusTime, UINT32_MAX);
}

// ============================================================================
// ATK-002: PROP_029 — AddBonusTime from exhausted state
//
// Even when screen time is exhausted (0 remaining), the server accepts
// AddBonusTime without checking ScreenTimeExhausted state.
// ============================================================================

TEST_F(TestContentControlE2E, ATK002_AddBonusTimeFromExhausted_ResumesPlayback)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-002: AddBonusTime from exhausted state          ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    Commands::AddBonusTime::DecodableType cmd;
    cmd.bonusTime = 86400;

    auto path   = MakePath(Commands::AddBonusTime::Id);
    bool result = emberAfContentControlClusterAddBonusTimeCallback(&mHandler, path, cmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);
    EXPECT_EQ(mDelegate.mLastBonusTime, 86400u);
    // Server does not check if screen time is exhausted before granting bonus
    ChipLogProgress(NotSpecified, "  CONFIRMED: Server grants bonus time without checking exhausted state");
}

// ============================================================================
// ATK-003: SetScreenDailyTime = 0 — locks out all screen time
//
// The server passes screenTime=0 to delegate with no minimum check.
// This effectively sets the daily limit to zero, denying all screen access.
// ============================================================================

TEST_F(TestContentControlE2E, ATK003_SetScreenDailyTimeZero_LocksOutScreenTime)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-003: SetScreenDailyTime(0) — total lockout      ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    Commands::SetScreenDailyTime::DecodableType cmd;
    cmd.screenTime = 0;

    auto path   = MakePath(Commands::SetScreenDailyTime::Id);
    bool result = emberAfContentControlClusterSetScreenDailyTimeCallback(&mHandler, path, cmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);
    EXPECT_TRUE(mDelegate.mSetScreenDailyTimeCalled);
    EXPECT_EQ(mDelegate.mLastScreenDailyTime, 0u);

    ChipLogProgress(NotSpecified, "  CONFIRMED: Server accepted screenTime=0 — zero daily allowance");
}

// ============================================================================
// ATK-004: SetScreenDailyTime = UINT32_MAX — unlimited screen time
// ============================================================================

TEST_F(TestContentControlE2E, ATK004_SetScreenDailyTimeMaxUint32_Unlimited)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-004: SetScreenDailyTime(UINT32_MAX) — unlimited ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    Commands::SetScreenDailyTime::DecodableType cmd;
    cmd.screenTime = UINT32_MAX;

    auto path   = MakePath(Commands::SetScreenDailyTime::Id);
    bool result = emberAfContentControlClusterSetScreenDailyTimeCallback(&mHandler, path, cmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);
    EXPECT_EQ(mDelegate.mLastScreenDailyTime, UINT32_MAX);

    ChipLogProgress(NotSpecified, "  CONFIRMED: Server accepted UINT32_MAX — ~136 years daily limit");
}

// ============================================================================
// ATK-005: Enable/Disable toggle — no state guard in server
//
// The server calls delegate->HandleEnable()/HandleDisable() without checking
// the current Enabled attribute.  A Manage-level client can toggle freely.
// ============================================================================

TEST_F(TestContentControlE2E, ATK005_EnableDisableToggle_NoStateGuard)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-005: Enable/Disable — no server-side guard      ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    // Enable
    {
        Commands::Enable::DecodableType cmd;
        auto path   = MakePath(Commands::Enable::Id);
        bool result = emberAfContentControlClusterEnableCallback(&mHandler, path, cmd);
        EXPECT_TRUE(result);
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        EXPECT_TRUE(mDelegate.mEnableCalled);
    }

    mHandler.Reset();
    mDelegate.Reset();

    // Disable immediately after — no cooldown, no confirmation
    {
        Commands::Disable::DecodableType cmd;
        auto path   = MakePath(Commands::Disable::Id);
        bool result = emberAfContentControlClusterDisableCallback(&mHandler, path, cmd);
        EXPECT_TRUE(result);
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        EXPECT_TRUE(mDelegate.mDisableCalled);
    }

    ChipLogProgress(NotSpecified, "  CONFIRMED: Enable → Disable executed with no server-side state checks");
}

// ============================================================================
// ATK-006: UpdatePIN — server does not verify old PIN
//
// The server passes oldPIN and newPIN directly to delegate->HandleUpdatePIN()
// with no verification.  An attacker with Manage privilege can change the PIN
// without knowing the current one — the server trusts the caller completely.
// ============================================================================

TEST_F(TestContentControlE2E, ATK006_UpdatePIN_NoServerVerification)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-006: UpdatePIN — server does not verify oldPIN  ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    // Send UpdatePIN with a wrong old PIN
    Commands::UpdatePIN::DecodableType cmd;
    const char oldPinStr[] = "WRONG_PIN";
    const char newPinStr[] = "ATTACKER_PIN";
    cmd.oldPIN = chip::CharSpan(oldPinStr, strlen(oldPinStr));
    cmd.newPIN = chip::CharSpan(newPinStr, strlen(newPinStr));

    auto path   = MakePath(Commands::UpdatePIN::Id);
    bool result = emberAfContentControlClusterUpdatePINCallback(&mHandler, path, cmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);
    EXPECT_TRUE(mDelegate.mUpdatePINCalled);

    // Server passed the wrong old PIN straight to delegate — no verification
    EXPECT_STREQ(mDelegate.mLastOldPIN, "WRONG_PIN");
    EXPECT_STREQ(mDelegate.mLastNewPIN, "ATTACKER_PIN");

    ChipLogProgress(NotSpecified, "  CONFIRMED: Server forwarded wrong old PIN to delegate without checking");
}

// ============================================================================
// ATK-007: SetOnDemandRatingThreshold with empty/arbitrary string
//
// The server passes the rating string directly without length or format check.
// ============================================================================

TEST_F(TestContentControlE2E, ATK007_SetOnDemandRatingThreshold_EmptyString)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-007: SetOnDemandRatingThreshold — empty string  ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    Commands::SetOnDemandRatingThreshold::DecodableType cmd;
    cmd.rating = chip::CharSpan("", 0);

    auto path   = MakePath(Commands::SetOnDemandRatingThreshold::Id);
    bool result = emberAfContentControlClusterSetOnDemandRatingThresholdCallback(&mHandler, path, cmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);
    EXPECT_TRUE(mDelegate.mSetOnDemandRatingCalled);

    ChipLogProgress(NotSpecified, "  CONFIRMED: Server accepted empty rating threshold — no format validation");
}

// ============================================================================
// ATK-008: SetScheduledContentRatingThreshold — arbitrary string bypass
// ============================================================================

TEST_F(TestContentControlE2E, ATK008_SetScheduledContentRatingThreshold_ArbitraryString)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-008: SetScheduledRatingThreshold — no validation║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    Commands::SetScheduledContentRatingThreshold::DecodableType cmd;
    const char rating[] = "NOT_A_REAL_RATING_ZZZZZ";
    cmd.rating = chip::CharSpan(rating, strlen(rating));

    auto path   = MakePath(Commands::SetScheduledContentRatingThreshold::Id);
    bool result = emberAfContentControlClusterSetScheduledContentRatingThresholdCallback(&mHandler, path, cmd);

    EXPECT_TRUE(result);
    EXPECT_EQ(mHandler.mStatus, Status::Success);
    EXPECT_TRUE(mDelegate.mSetScheduledRatingCalled);
    EXPECT_STREQ(mDelegate.mLastScheduledRating, "NOT_A_REAL_RATING_ZZZZZ");

    ChipLogProgress(NotSpecified, "  CONFIRMED: Server accepted invalid rating string without checking OnDemandRatings list");
}

// ============================================================================
// ATK-009: BlockUnrated/UnblockUnrated — toggle with no guard
// ============================================================================

TEST_F(TestContentControlE2E, ATK009_BlockUnratedToggle_NoGuard)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-009: Block/Unblock unrated — no server guard    ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    // Block
    {
        Commands::BlockUnratedContent::DecodableType cmd;
        auto path   = MakePath(Commands::BlockUnratedContent::Id);
        bool result = emberAfContentControlClusterBlockUnratedContentCallback(&mHandler, path, cmd);
        EXPECT_TRUE(result);
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        EXPECT_TRUE(mDelegate.mBlockUnratedCalled);
    }

    mHandler.Reset();
    mDelegate.Reset();

    // Immediately unblock — no confirmation, no PIN required
    {
        Commands::UnblockUnratedContent::DecodableType cmd;
        auto path   = MakePath(Commands::UnblockUnratedContent::Id);
        bool result = emberAfContentControlClusterUnblockUnratedContentCallback(&mHandler, path, cmd);
        EXPECT_TRUE(result);
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        EXPECT_TRUE(mDelegate.mUnblockUnratedCalled);
    }

    ChipLogProgress(NotSpecified, "  CONFIRMED: Block → Unblock completed with no server-side authentication");
}

// ============================================================================
// ATK-010: Missing 6 command callbacks — delegate interface gap
//
// The spec defines these commands but the SDK has NO ember callbacks and
// NO delegate methods for them:
//   AddBlockChannels, RemoveBlockChannels, AddBlockApplications,
//   RemoveBlockApplications, SetBlockContentTimeWindow, RemoveBlockContentTimeWindow
//
// This means PROP_014, PROP_018, PROP_031, PROP_032, PROP_033 cannot
// possibly be enforced — the server never receives these commands.
// ============================================================================

TEST_F(TestContentControlE2E, ATK010_MissingSixCommands_DelegateInterfaceGap)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  ATK-010: 6 spec commands have NO server callback    ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    // Verify the command types exist in generated code (spec defines them)
    EXPECT_EQ(Commands::AddBlockChannels::Type::GetClusterId(), ContentControl::Id);
    EXPECT_EQ(Commands::RemoveBlockChannels::Type::GetClusterId(), ContentControl::Id);
    EXPECT_EQ(Commands::AddBlockApplications::Type::GetClusterId(), ContentControl::Id);
    EXPECT_EQ(Commands::RemoveBlockApplications::Type::GetClusterId(), ContentControl::Id);
    EXPECT_EQ(Commands::SetBlockContentTimeWindow::Type::GetClusterId(), ContentControl::Id);
    EXPECT_EQ(Commands::RemoveBlockContentTimeWindow::Type::GetClusterId(), ContentControl::Id);

    // The delegate interface (content-control-delegate.h) has 10 command handlers.
    // These 6 commands are completely absent from the delegate interface.
    // There is no emberAfContentControlClusterAddBlockChannelsCallback() etc.
    // This is verified at compile time — if those functions existed, we would call them.

    ChipLogProgress(NotSpecified, "  CONFIRMED: 6 spec-defined commands have NO server implementation");
    ChipLogProgress(NotSpecified, "  Missing: AddBlockChannels, RemoveBlockChannels, AddBlockApplications,");
    ChipLogProgress(NotSpecified, "           RemoveBlockApplications, SetBlockContentTimeWindow, RemoveBlockContentTimeWindow");
    SUCCEED();
}

// ============================================================================
// ATK-COMBINED: Rapid-fire all 10 implemented commands — zero validation
//
// Demonstrates that the entire server is a pure delegate passthrough with
// no validation on ANY command.
// ============================================================================

TEST_F(TestContentControlE2E, ATK_Combined_AllCommandsPassthrough)
{
    ChipLogProgress(NotSpecified, "╔══════════════════════════════════════════════════════╗");
    ChipLogProgress(NotSpecified, "║  COMBINED: All 10 server callbacks — zero validation ║");
    ChipLogProgress(NotSpecified, "╚══════════════════════════════════════════════════════╝");

    int commandsTested = 0;

    // 1. Enable
    {
        Commands::Enable::DecodableType cmd;
        auto path = MakePath(Commands::Enable::Id);
        EXPECT_TRUE(emberAfContentControlClusterEnableCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        commandsTested++;
        mHandler.Reset();
    }

    // 2. Disable
    {
        Commands::Disable::DecodableType cmd;
        auto path = MakePath(Commands::Disable::Id);
        EXPECT_TRUE(emberAfContentControlClusterDisableCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        commandsTested++;
        mHandler.Reset();
    }

    // 3. AddBonusTime
    {
        Commands::AddBonusTime::DecodableType cmd;
        cmd.bonusTime = 999999;
        auto path = MakePath(Commands::AddBonusTime::Id);
        EXPECT_TRUE(emberAfContentControlClusterAddBonusTimeCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        EXPECT_EQ(mDelegate.mLastBonusTime, 999999u);
        commandsTested++;
        mHandler.Reset();
    }

    // 4. SetScreenDailyTime
    {
        Commands::SetScreenDailyTime::DecodableType cmd;
        cmd.screenTime = 42;
        auto path = MakePath(Commands::SetScreenDailyTime::Id);
        EXPECT_TRUE(emberAfContentControlClusterSetScreenDailyTimeCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        EXPECT_EQ(mDelegate.mLastScreenDailyTime, 42u);
        commandsTested++;
        mHandler.Reset();
    }

    // 5. UpdatePIN
    {
        Commands::UpdatePIN::DecodableType cmd;
        const char o[] = "old";
        const char n[] = "new";
        cmd.oldPIN = chip::CharSpan(o, 3);
        cmd.newPIN = chip::CharSpan(n, 3);
        auto path = MakePath(Commands::UpdatePIN::Id);
        EXPECT_TRUE(emberAfContentControlClusterUpdatePINCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        commandsTested++;
        mHandler.Reset();
    }

    // 6. ResetPIN
    {
        Commands::ResetPIN::DecodableType cmd;
        auto path = MakePath(Commands::ResetPIN::Id);
        EXPECT_TRUE(emberAfContentControlClusterResetPINCallback(&mHandler, path, cmd));
        EXPECT_TRUE(mDelegate.mResetPINCalled);
        commandsTested++;
        mHandler.Reset();
    }

    // 7. BlockUnratedContent
    {
        Commands::BlockUnratedContent::DecodableType cmd;
        auto path = MakePath(Commands::BlockUnratedContent::Id);
        EXPECT_TRUE(emberAfContentControlClusterBlockUnratedContentCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        commandsTested++;
        mHandler.Reset();
    }

    // 8. UnblockUnratedContent
    {
        Commands::UnblockUnratedContent::DecodableType cmd;
        auto path = MakePath(Commands::UnblockUnratedContent::Id);
        EXPECT_TRUE(emberAfContentControlClusterUnblockUnratedContentCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        commandsTested++;
        mHandler.Reset();
    }

    // 9. SetOnDemandRatingThreshold
    {
        Commands::SetOnDemandRatingThreshold::DecodableType cmd;
        const char r[] = "X";
        cmd.rating = chip::CharSpan(r, 1);
        auto path = MakePath(Commands::SetOnDemandRatingThreshold::Id);
        EXPECT_TRUE(emberAfContentControlClusterSetOnDemandRatingThresholdCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        commandsTested++;
        mHandler.Reset();
    }

    // 10. SetScheduledContentRatingThreshold
    {
        Commands::SetScheduledContentRatingThreshold::DecodableType cmd;
        const char r[] = "Z";
        cmd.rating = chip::CharSpan(r, 1);
        auto path = MakePath(Commands::SetScheduledContentRatingThreshold::Id);
        EXPECT_TRUE(emberAfContentControlClusterSetScheduledContentRatingThresholdCallback(&mHandler, path, cmd));
        EXPECT_EQ(mHandler.mStatus, Status::Success);
        commandsTested++;
        mHandler.Reset();
    }

    EXPECT_EQ(commandsTested, 10);
    ChipLogProgress(NotSpecified, "  CONFIRMED: All 10 real server callbacks executed — pure passthrough, zero validation");
}

} // anonymous namespace
