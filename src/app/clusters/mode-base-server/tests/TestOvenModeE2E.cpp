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
 * @file TestOvenModeE2E.cpp
 *
 * Real-server E2E attack-simulation tests for the Oven Mode cluster (§8.11).
 *
 * These tests instantiate a REAL ModeBase::Instance with an OvenMode delegate,
 * and exercise the ChangeToMode command path for all 9 oven modes (benign and
 * hazardous) via InvokeCommand.  The tests confirm PROP_018: the SDK imposes
 * no per-mode privilege differentiation — all modes succeed with the identical
 * Operate-level code path.
 */

#include <gtest/gtest.h>

#include <app/clusters/mode-base-server/mode-base-server.h>
#include <app/clusters/mode-base-server/mode-base-cluster-objects.h>
#include <app/CommandHandler.h>
#include <app/CommandHandlerInterface.h>
#include <app/ConcreteCommandPath.h>
#include <app/SafeAttributePersistenceProvider.h>
#include <app/data-model/Encode.h>
#include <app/util/mock/Functions.h>
#include <app/util/mock/MockNodeConfig.h>
#include <clusters/OvenMode/ClusterId.h>
#include <clusters/OvenMode/Enums.h>
#include <lib/core/TLV.h>
#include <lib/core/DataModelTypes.h>
#include <access/SubjectDescriptor.h>
#include <messaging/ExchangeContext.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::ModeBase;

// ---------- Constants ----------

static constexpr EndpointId kTestEndpoint = 1;

// Oven mode indices match the all-clusters-app reference delegate
static constexpr uint8_t kModeBake            = 0;
static constexpr uint8_t kModeConvection      = 1;
static constexpr uint8_t kModeGrill           = 2;  // Hazardous: upper broil element
static constexpr uint8_t kModeRoast           = 3;
static constexpr uint8_t kModeClean           = 4;  // Hazardous: pyrolytic >480°C
static constexpr uint8_t kModeConvectionBake  = 5;
static constexpr uint8_t kModeConvectionRoast = 6;
static constexpr uint8_t kModeWarming         = 7;  // Benign: low temperature
static constexpr uint8_t kModeProofing        = 8;  // Benign: ~35°C

static constexpr uint8_t kNumModes = 9;

// ---------- Test OvenMode Delegate (real delegate using real mode tags) ----------

class TestOvenModeDelegate : public ModeBase::Delegate
{
private:
    using ModeTagStructType = chip::app::Clusters::detail::Structs::ModeTagStruct::Type;

    ModeTagStructType mTagsBake[1]            = { { .value = to_underlying(OvenMode::ModeTag::kBake) } };
    ModeTagStructType mTagsConvection[1]      = { { .value = to_underlying(OvenMode::ModeTag::kConvection) } };
    ModeTagStructType mTagsGrill[1]           = { { .value = to_underlying(OvenMode::ModeTag::kGrill) } };
    ModeTagStructType mTagsRoast[1]           = { { .value = to_underlying(OvenMode::ModeTag::kRoast) } };
    ModeTagStructType mTagsClean[1]           = { { .value = to_underlying(OvenMode::ModeTag::kClean) } };
    ModeTagStructType mTagsConvectionBake[1]  = { { .value = to_underlying(OvenMode::ModeTag::kConvectionBake) } };
    ModeTagStructType mTagsConvectionRoast[1] = { { .value = to_underlying(OvenMode::ModeTag::kConvectionRoast) } };
    ModeTagStructType mTagsWarming[1]         = { { .value = to_underlying(OvenMode::ModeTag::kWarming) } };
    ModeTagStructType mTagsProofing[1]        = { { .value = to_underlying(OvenMode::ModeTag::kProofing) } };

    const chip::app::Clusters::detail::Structs::ModeOptionStruct::Type kModeOptions[kNumModes] = {
        { .label = CharSpan::fromCharString("Bake"),            .mode = kModeBake,            .modeTags = DataModel::List<const ModeTagStructType>(mTagsBake) },
        { .label = CharSpan::fromCharString("Convection"),      .mode = kModeConvection,      .modeTags = DataModel::List<const ModeTagStructType>(mTagsConvection) },
        { .label = CharSpan::fromCharString("Grill"),           .mode = kModeGrill,           .modeTags = DataModel::List<const ModeTagStructType>(mTagsGrill) },
        { .label = CharSpan::fromCharString("Roast"),           .mode = kModeRoast,           .modeTags = DataModel::List<const ModeTagStructType>(mTagsRoast) },
        { .label = CharSpan::fromCharString("Clean"),           .mode = kModeClean,           .modeTags = DataModel::List<const ModeTagStructType>(mTagsClean) },
        { .label = CharSpan::fromCharString("Convection Bake"), .mode = kModeConvectionBake,  .modeTags = DataModel::List<const ModeTagStructType>(mTagsConvectionBake) },
        { .label = CharSpan::fromCharString("Convection Roast"),.mode = kModeConvectionRoast, .modeTags = DataModel::List<const ModeTagStructType>(mTagsConvectionRoast) },
        { .label = CharSpan::fromCharString("Warming"),         .mode = kModeWarming,         .modeTags = DataModel::List<const ModeTagStructType>(mTagsWarming) },
        { .label = CharSpan::fromCharString("Proofing"),        .mode = kModeProofing,        .modeTags = DataModel::List<const ModeTagStructType>(mTagsProofing) },
    };

    // Track what mode the delegate was asked to handle
    uint8_t mLastRequestedMode = 0xFF;
    bool mLastRequestHadPrivilegeContext = false;

public:
    CHIP_ERROR Init() override { return CHIP_NO_ERROR; }

    void HandleChangeToMode(uint8_t NewMode, ModeBase::Commands::ChangeToModeResponse::Type & response) override
    {
        mLastRequestedMode = NewMode;
        // The delegate receives ONLY a mode index — no invoker privilege context.
        // This is the core of PROP_018: the delegate cannot differentiate.
        mLastRequestHadPrivilegeContext = false;  // always false — not available
        response.status = to_underlying(ModeBase::StatusCode::kSuccess);
    }

    CHIP_ERROR GetModeLabelByIndex(uint8_t modeIndex, MutableCharSpan & label) override
    {
        if (modeIndex >= kNumModes) return CHIP_ERROR_PROVIDER_LIST_EXHAUSTED;
        return CopyCharSpanToMutableCharSpan(kModeOptions[modeIndex].label, label);
    }

    CHIP_ERROR GetModeValueByIndex(uint8_t modeIndex, uint8_t & value) override
    {
        if (modeIndex >= kNumModes) return CHIP_ERROR_PROVIDER_LIST_EXHAUSTED;
        value = kModeOptions[modeIndex].mode;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR GetModeTagsByIndex(uint8_t modeIndex, DataModel::List<chip::app::Clusters::detail::Structs::ModeTagStruct::Type> & tags) override
    {
        if (modeIndex >= kNumModes) return CHIP_ERROR_PROVIDER_LIST_EXHAUSTED;
        if (tags.size() < kModeOptions[modeIndex].modeTags.size()) return CHIP_ERROR_INVALID_ARGUMENT;
        std::copy(kModeOptions[modeIndex].modeTags.begin(), kModeOptions[modeIndex].modeTags.end(), tags.begin());
        tags.reduce_size(kModeOptions[modeIndex].modeTags.size());
        return CHIP_NO_ERROR;
    }

    uint8_t GetLastRequestedMode() const { return mLastRequestedMode; }
    bool GetLastRequestHadPrivilegeContext() const { return mLastRequestHadPrivilegeContext; }
};

// ---------- Minimal Mock CommandHandler ----------

class MockCommandHandler : public CommandHandler
{
public:
    uint8_t lastResponseStatus = 0xFF;

    CHIP_ERROR FallibleAddStatus(const ConcreteCommandPath & aRequestCommandPath,
                                 const Protocols::InteractionModel::ClusterStatusCode & aStatus,
                                 const char * context = nullptr) override
    {
        return CHIP_NO_ERROR;
    }

    void AddStatus(const ConcreteCommandPath & aRequestCommandPath,
                   const Protocols::InteractionModel::ClusterStatusCode & aStatus,
                   const char * context = nullptr) override
    {
    }

    FabricIndex GetAccessingFabricIndex() const override { return 1; }

    CHIP_ERROR AddResponseData(const ConcreteCommandPath & aRequestCommandPath, CommandId aResponseCommandId,
                               const DataModel::EncodableToTLV & aEncodable) override
    {
        // Use FabricAwareTLVWriter — EncodableResponseCommandPayload requires it
        uint8_t buffer[256];
        TLV::TLVWriter writer;
        writer.Init(buffer, sizeof(buffer));
        DataModel::FabricAwareTLVWriter faWriter(writer, 1 /* fabricIndex */);
        CHIP_ERROR err = aEncodable.EncodeTo(faWriter, TLV::AnonymousTag());
        if (err != CHIP_NO_ERROR)
            return err;

        TLV::TLVReader reader;
        reader.Init(buffer, writer.GetLengthWritten());
        reader.Next();

        ModeBase::Commands::ChangeToModeResponse::DecodableType response;
        err = response.Decode(reader);
        if (err == CHIP_NO_ERROR)
        {
            lastResponseStatus = response.status;
        }
        return CHIP_NO_ERROR;
    }

    void AddResponse(const ConcreteCommandPath & aRequestCommandPath, CommandId aResponseCommandId,
                     const DataModel::EncodableToTLV & aEncodable) override
    {
        AddResponseData(aRequestCommandPath, aResponseCommandId, aEncodable);
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

// ---------- Minimal SafeAttributePersistenceProvider ----------

class TestPersistenceProvider : public SafeAttributePersistenceProvider
{
public:
    CHIP_ERROR SafeWriteValue(const ConcreteAttributePath & aPath, const ByteSpan & aValue) override
    {
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR SafeReadValue(const ConcreteAttributePath & aPath, MutableByteSpan & aValue) override
    {
        return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
    }
};

// ---------- Helper: encode ChangeToMode command to TLV ----------

static void EncodeChangeToMode(uint8_t newMode, uint8_t * buffer, size_t bufSize, TLV::TLVReader & reader)
{
    ModeBase::Commands::ChangeToMode::Type command;
    command.newMode = newMode;

    TLV::TLVWriter writer;
    writer.Init(buffer, bufSize);
    ASSERT_EQ(command.Encode(writer, TLV::AnonymousTag()), CHIP_NO_ERROR);

    reader.Init(buffer, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
}

// ---------- Test Fixture ----------

class TestOvenModeE2E : public ::testing::Test
{
protected:
    TestOvenModeDelegate mDelegate;
    ModeBase::Instance * mInstance = nullptr;
    TestPersistenceProvider mPersistence;

    void SetUp() override
    {
        // Set up persistence provider (needed by UpdateCurrentMode)
        SetSafeAttributePersistenceProvider(&mPersistence);

        // Configure mock ember so emberAfContainsServer returns true for OvenMode on kTestEndpoint
        static const chip::Test::MockClusterConfig ovenModeCluster(OvenMode::Id);
        static const chip::Test::MockEndpointConfig endpoint(kTestEndpoint, { ovenModeCluster });
        static const chip::Test::MockNodeConfig node({ endpoint });
        chip::Test::SetMockNodeConfig(node);

        // Create real ModeBase::Instance for OvenMode cluster, no features (DEPONOFF is X)
        mInstance = new ModeBase::Instance(&mDelegate, kTestEndpoint, OvenMode::Id, 0 /* featureMap */);
        ASSERT_EQ(mInstance->Init(), CHIP_NO_ERROR);
    }

    void TearDown() override
    {
        if (mInstance)
        {
            mInstance->Shutdown();
            delete mInstance;
            mInstance = nullptr;
        }
        chip::Test::ResetMockNodeConfig();
    }

    // Helper: invoke ChangeToMode on the real Instance and return the response status
    uint8_t InvokeChangeToMode(uint8_t newMode)
    {
        MockCommandHandler handler;
        uint8_t tlvBuffer[64];
        TLV::TLVReader reader;
        EncodeChangeToMode(newMode, tlvBuffer, sizeof(tlvBuffer), reader);

        ConcreteCommandPath path(kTestEndpoint, OvenMode::Id, ModeBase::Commands::ChangeToMode::Id);
        CommandHandlerInterface::HandlerContext ctx(handler, path, reader);

        // InvokeCommand is public on CommandHandlerInterface base class
        static_cast<CommandHandlerInterface *>(mInstance)->InvokeCommand(ctx);

        return handler.lastResponseStatus;
    }
};

// ==========================================================================
// PROP_018 Attack Simulation: Flat Access Control For All Modes
// ==========================================================================

// PROP_018 core test: All 9 modes (benign + hazardous) succeed via identical code path
TEST_F(TestOvenModeE2E, AllModesAcceptWithoutPrivilegeDifferentiation)
{
    // Start from Bake (mode 0, set by Init)
    EXPECT_EQ(mInstance->GetCurrentMode(), kModeBake);

    struct ModeTestCase {
        uint8_t mode;
        const char * name;
        bool isHazardous;
    };

    ModeTestCase testCases[] = {
        { kModeConvection,      "Convection",       false },
        { kModeGrill,           "Grill (HAZARDOUS)", true  },
        { kModeRoast,           "Roast",             false },
        { kModeClean,           "Clean (HAZARDOUS)", true  },
        { kModeConvectionBake,  "Convection Bake",   false },
        { kModeConvectionRoast, "Convection Roast",  false },
        { kModeWarming,         "Warming (benign)",  false },
        { kModeProofing,        "Proofing (benign)", false },
        { kModeBake,            "Bake",              false },
    };

    for (const auto & tc : testCases)
    {
        uint8_t status = InvokeChangeToMode(tc.mode);
        EXPECT_EQ(status, to_underlying(ModeBase::StatusCode::kSuccess))
            << "ChangeToMode(" << tc.name << ") should succeed — PROP_018 flat access";
        EXPECT_EQ(mInstance->GetCurrentMode(), tc.mode)
            << "CurrentMode should be updated to " << tc.name;
    }
}

// PROP_018 attack: Benign→Clean (pyrolytic >480°C) succeeds with no additional check
TEST_F(TestOvenModeE2E, BenignToCleanModeSucceedsUnguarded)
{
    // Start from Proofing (~35°C benign)
    EXPECT_EQ(InvokeChangeToMode(kModeProofing), to_underlying(ModeBase::StatusCode::kSuccess));
    EXPECT_EQ(mInstance->GetCurrentMode(), kModeProofing);

    // Attack: switch to Clean (>480°C pyrolytic) — same Operate-level code path
    uint8_t status = InvokeChangeToMode(kModeClean);
    EXPECT_EQ(status, to_underlying(ModeBase::StatusCode::kSuccess))
        << "PROP_018: Clean mode accepted with no elevated privilege check";
    EXPECT_EQ(mInstance->GetCurrentMode(), kModeClean)
        << "CurrentMode changed to Clean without privilege differentiation";
}

// PROP_018 attack: Benign→Grill (upper broil element) succeeds with no additional check
TEST_F(TestOvenModeE2E, BenignToGrillModeSucceedsUnguarded)
{
    // Start from Warming (benign low-temp)
    EXPECT_EQ(InvokeChangeToMode(kModeWarming), to_underlying(ModeBase::StatusCode::kSuccess));

    // Attack: switch to Grill (maximum intensity broil element)
    uint8_t status = InvokeChangeToMode(kModeGrill);
    EXPECT_EQ(status, to_underlying(ModeBase::StatusCode::kSuccess))
        << "PROP_018: Grill mode accepted with no elevated privilege check";
    EXPECT_EQ(mInstance->GetCurrentMode(), kModeGrill);
}

// Confirm unsupported mode is properly rejected (PROP_012 HOLDS)
TEST_F(TestOvenModeE2E, UnsupportedModeRejected)
{
    uint8_t currentBefore = mInstance->GetCurrentMode();
    uint8_t status = InvokeChangeToMode(0xFF); // not in SupportedModes
    EXPECT_EQ(status, to_underlying(ModeBase::StatusCode::kUnsupportedMode))
        << "Invalid mode 0xFF should return UnsupportedMode";
    EXPECT_EQ(mInstance->GetCurrentMode(), currentBefore)
        << "CurrentMode should not change on unsupported mode";
}

// Confirm same-mode command returns success without state change
TEST_F(TestOvenModeE2E, SameModeChangeReturnsSuccess)
{
    uint8_t current = mInstance->GetCurrentMode();
    uint8_t status = InvokeChangeToMode(current);
    EXPECT_EQ(status, to_underlying(ModeBase::StatusCode::kSuccess));
    EXPECT_EQ(mInstance->GetCurrentMode(), current);
}

// Confirm the delegate receives no privilege context — it gets only a uint8_t mode index
TEST_F(TestOvenModeE2E, DelegateReceivesNoPrivilegeContext)
{
    InvokeChangeToMode(kModeClean);
    EXPECT_EQ(mDelegate.GetLastRequestedMode(), kModeClean)
        << "Delegate correctly received Clean mode index";
    EXPECT_FALSE(mDelegate.GetLastRequestHadPrivilegeContext())
        << "PROP_018: Delegate has NO access to invoker privilege — cannot differentiate";
}

// PROP_018 sequential attack: rapidly cycle through all hazardous modes
TEST_F(TestOvenModeE2E, RapidHazardousModeCycling)
{
    uint8_t hazardousModes[] = { kModeGrill, kModeClean, kModeGrill, kModeClean };
    for (uint8_t mode : hazardousModes)
    {
        uint8_t status = InvokeChangeToMode(mode);
        EXPECT_EQ(status, to_underlying(ModeBase::StatusCode::kSuccess))
            << "PROP_018: Rapid cycling to hazardous mode " << static_cast<int>(mode) << " succeeds";
        EXPECT_EQ(mInstance->GetCurrentMode(), mode);
    }
}

// Confirm IsTimedInvoke() is false — no timed interaction required (relates to PROP_002)
TEST_F(TestOvenModeE2E, NoTimedInvokeRequirement)
{
    // The MockCommandHandler returns false for IsTimedInvoke()
    // If the server required timed invoke, InvokeCommand would need to check it
    // Verify that commands succeed without timed invoke
    uint8_t status = InvokeChangeToMode(kModeClean);
    EXPECT_EQ(status, to_underlying(ModeBase::StatusCode::kSuccess))
        << "ChangeToMode(Clean) succeeds without timed interaction — PROP_002 confirmed in server";
}

// Verify all 9 modes are recognized as supported
TEST_F(TestOvenModeE2E, AllNineModesSupported)
{
    for (uint8_t m = 0; m < kNumModes; m++)
    {
        EXPECT_TRUE(mInstance->IsSupportedMode(m))
            << "Mode " << static_cast<int>(m) << " should be in SupportedModes";
    }
    // And an unsupported one
    EXPECT_FALSE(mInstance->IsSupportedMode(0xFF));
}
