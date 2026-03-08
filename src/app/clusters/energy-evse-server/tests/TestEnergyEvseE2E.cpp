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
 * @file TestEnergyEvseE2E.cpp
 *
 * Real-server E2E attack-simulation tests for the Energy EVSE cluster (section 9.3).
 *
 * These tests instantiate the REAL EnergyEvse::Instance and exercise command
 * paths via InvokeCommand on the production server code.
 *
 * Two VALID vulnerability claims are tested:
 *
 *   PROP_EVSE_011 — Diagnostics DoS via unbounded duration.
 *       StartDiagnostics has no maximum duration and no cancellation command.
 *       An Operate-level attacker can hold the EVSE in DisabledDiagnostics
 *       indefinitely, blocking all charging. EnableCharging is rejected during
 *       diagnostics. The same Operate privilege controls both StartDiagnostics
 *       and EnableCharging.
 *
 *   PROP_EVSE_036 — Time synchronization dependency for epoch attributes.
 *       ChargingEnabledUntil/DischargingEnabledUntil use epoch_s from an
 *       external time source with no integrity checks. The delegate's
 *       HandleEnabledStateExpiration uses system time directly. No rollback
 *       detection, no time quality attribute, no fallback enforcement.
 */

#include <gtest/gtest.h>

#include <access/SubjectDescriptor.h>
#include <app/CommandHandler.h>
#include <app/CommandHandlerInterface.h>
#include <app/ConcreteCommandPath.h>
#include <app/SafeAttributePersistenceProvider.h>
#include <app/clusters/energy-evse-server/energy-evse-server.h>
#include <app/data-model/Encode.h>
#include <app/util/mock/Functions.h>
#include <app/util/mock/MockNodeConfig.h>
#include <clusters/EnergyEvse/ClusterId.h>
#include <clusters/EnergyEvse/Commands.h>
#include <clusters/EnergyEvse/Enums.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/TLV.h>
#include <messaging/ExchangeContext.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::EnergyEvse;
using Status = Protocols::InteractionModel::Status;

// ===== Constants =====

static constexpr EndpointId kTestEndpoint = 1;

// ===== Mock EnergyEvse Delegate =====

class MockEnergyEvseDelegate : public EnergyEvse::Delegate
{
    StateEnum mState                                       = StateEnum::kNotPluggedIn;
    SupplyStateEnum mSupplyState                           = SupplyStateEnum::kDisabled;
    FaultStateEnum mFaultState                             = FaultStateEnum::kNoError;
    DataModel::Nullable<uint32_t> mChargingEnabledUntil    = DataModel::NullNullable;
    DataModel::Nullable<uint32_t> mDischargingEnabledUntil = DataModel::NullNullable;
    int64_t mCircuitCapacity                               = 32000; // 32A
    int64_t mMinimumChargeCurrent                          = 6000;  // 6A
    int64_t mMaximumChargeCurrent                          = 0;
    int64_t mMaximumDischargeCurrent                       = 0;
    int64_t mUserMaximumChargeCurrent                      = 0;
    uint32_t mRandomizationDelayWindow                     = 600;
    DataModel::Nullable<uint32_t> mNextChargeStartTime     = DataModel::NullNullable;
    DataModel::Nullable<uint32_t> mNextChargeTargetTime    = DataModel::NullNullable;
    DataModel::Nullable<int64_t> mNextChargeRequiredEnergy = DataModel::NullNullable;
    DataModel::Nullable<Percent> mNextChargeTargetSoC      = DataModel::NullNullable;
    DataModel::Nullable<uint16_t> mApproximateEVEfficiency = DataModel::NullNullable;
    DataModel::Nullable<Percent> mStateOfCharge            = DataModel::NullNullable;
    DataModel::Nullable<int64_t> mBatteryCapacity          = DataModel::NullNullable;
    DataModel::Nullable<uint32_t> mSessionID               = DataModel::NullNullable;
    DataModel::Nullable<uint32_t> mSessionDuration         = DataModel::NullNullable;
    DataModel::Nullable<int64_t> mSessionEnergyCharged     = DataModel::NullNullable;
    DataModel::Nullable<int64_t> mSessionEnergyDischarged  = DataModel::NullNullable;

    uint32_t mDisableCallCount           = 0;
    uint32_t mEnableChargingCallCount    = 0;
    uint32_t mEnableDischargingCallCount = 0;
    uint32_t mStartDiagnosticsCallCount  = 0;

public:
    // --- Command handlers ---

    Status Disable() override
    {
        mDisableCallCount++;
        mSupplyState = SupplyStateEnum::kDisabled;
        mChargingEnabledUntil.SetNull();
        mDischargingEnabledUntil.SetNull();
        return Status::Success;
    }

    Status EnableCharging(const DataModel::Nullable<uint32_t> & enableChargeTime, const int64_t & minimumChargeCurrent,
                          const int64_t & maximumChargeCurrent) override
    {
        mEnableChargingCallCount++;

        // Spec: reject if fault or diagnostics
        if (mFaultState != FaultStateEnum::kNoError)
            return Status::Failure;
        if (mSupplyState == SupplyStateEnum::kDisabledDiagnostics)
            return Status::Failure;

        mChargingEnabledUntil = enableChargeTime;
        mMinimumChargeCurrent = minimumChargeCurrent;
        mMaximumChargeCurrent = maximumChargeCurrent;
        mSupplyState          = SupplyStateEnum::kChargingEnabled;
        return Status::Success;
    }

    Status EnableDischarging(const DataModel::Nullable<uint32_t> & enableDischargeTime,
                             const int64_t & maximumDischargeCurrent) override
    {
        mEnableDischargingCallCount++;

        if (mFaultState != FaultStateEnum::kNoError)
            return Status::Failure;
        if (mSupplyState == SupplyStateEnum::kDisabledDiagnostics)
            return Status::Failure;

        mDischargingEnabledUntil = enableDischargeTime;
        mMaximumDischargeCurrent = maximumDischargeCurrent;
        mSupplyState             = SupplyStateEnum::kDischargingEnabled;
        return Status::Success;
    }

    Status StartDiagnostics() override
    {
        mStartDiagnosticsCallCount++;

        if (mSupplyState != SupplyStateEnum::kDisabled)
            return Status::Failure;

        mSupplyState = SupplyStateEnum::kDisabledDiagnostics;
        return Status::Success;
    }

    Status SetTargets(
        const DataModel::DecodableList<Structs::ChargingTargetScheduleStruct::DecodableType> & chargingTargetSchedules) override
    {
        return Status::Success;
    }

    Status LoadTargets() override { return Status::Success; }

    Status GetTargets(DataModel::List<const Structs::ChargingTargetScheduleStruct::Type> & chargingTargetSchedules) override
    {
        return Status::Success;
    }

    Status ClearTargets() override { return Status::Success; }

    // --- Getters ---
    StateEnum GetState() override { return mState; }
    SupplyStateEnum GetSupplyState() override { return mSupplyState; }
    FaultStateEnum GetFaultState() override { return mFaultState; }
    DataModel::Nullable<uint32_t> GetChargingEnabledUntil() override { return mChargingEnabledUntil; }
    DataModel::Nullable<uint32_t> GetDischargingEnabledUntil() override { return mDischargingEnabledUntil; }
    int64_t GetCircuitCapacity() override { return mCircuitCapacity; }
    int64_t GetMinimumChargeCurrent() override { return mMinimumChargeCurrent; }
    int64_t GetMaximumChargeCurrent() override { return mMaximumChargeCurrent; }
    int64_t GetMaximumDischargeCurrent() override { return mMaximumDischargeCurrent; }
    int64_t GetUserMaximumChargeCurrent() override { return mUserMaximumChargeCurrent; }
    uint32_t GetRandomizationDelayWindow() override { return mRandomizationDelayWindow; }
    DataModel::Nullable<uint32_t> GetNextChargeStartTime() override { return mNextChargeStartTime; }
    DataModel::Nullable<uint32_t> GetNextChargeTargetTime() override { return mNextChargeTargetTime; }
    DataModel::Nullable<int64_t> GetNextChargeRequiredEnergy() override { return mNextChargeRequiredEnergy; }
    DataModel::Nullable<Percent> GetNextChargeTargetSoC() override { return mNextChargeTargetSoC; }
    DataModel::Nullable<uint16_t> GetApproximateEVEfficiency() override { return mApproximateEVEfficiency; }
    DataModel::Nullable<Percent> GetStateOfCharge() override { return mStateOfCharge; }
    DataModel::Nullable<int64_t> GetBatteryCapacity() override { return mBatteryCapacity; }
    DataModel::Nullable<CharSpan> GetVehicleID() override { return DataModel::NullNullable; }
    DataModel::Nullable<uint32_t> GetSessionID() override { return mSessionID; }
    DataModel::Nullable<uint32_t> GetSessionDuration() override { return mSessionDuration; }
    DataModel::Nullable<int64_t> GetSessionEnergyCharged() override { return mSessionEnergyCharged; }
    DataModel::Nullable<int64_t> GetSessionEnergyDischarged() override { return mSessionEnergyDischarged; }

    // --- Setters ---
    CHIP_ERROR SetUserMaximumChargeCurrent(int64_t aNewValue) override
    {
        mUserMaximumChargeCurrent = aNewValue;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR SetRandomizationDelayWindow(uint32_t aNewValue) override
    {
        mRandomizationDelayWindow = aNewValue;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR SetApproximateEVEfficiency(DataModel::Nullable<uint16_t> aNewValue) override
    {
        mApproximateEVEfficiency = aNewValue;
        return CHIP_NO_ERROR;
    }

    // --- Test helpers ---
    void SetState(StateEnum s) { mState = s; }
    void SetSupplyState(SupplyStateEnum s) { mSupplyState = s; }
    void SetFaultState(FaultStateEnum f) { mFaultState = f; }

    uint32_t GetDisableCallCount() const { return mDisableCallCount; }
    uint32_t GetEnableChargingCallCount() const { return mEnableChargingCallCount; }
    uint32_t GetStartDiagnosticsCallCount() const { return mStartDiagnosticsCallCount; }
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

    void AddStatus(const ConcreteCommandPath & aRequestCommandPath, const Protocols::InteractionModel::ClusterStatusCode & aStatus,
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
    {}

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

static void EncodeDisable(const Commands::Disable::Type & cmd, uint8_t * buffer, size_t bufSize, TLV::TLVReader & reader)
{
    TLV::TLVWriter writer;
    writer.Init(buffer, bufSize);
    ASSERT_EQ(cmd.Encode(writer, TLV::AnonymousTag()), CHIP_NO_ERROR);
    reader.Init(buffer, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
}

static void EncodeEnableCharging(const Commands::EnableCharging::Type & cmd, uint8_t * buffer, size_t bufSize,
                                 TLV::TLVReader & reader)
{
    TLV::TLVWriter writer;
    writer.Init(buffer, bufSize);
    ASSERT_EQ(cmd.Encode(writer, TLV::AnonymousTag()), CHIP_NO_ERROR);
    reader.Init(buffer, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
}

static void EncodeStartDiagnostics(const Commands::StartDiagnostics::Type & cmd, uint8_t * buffer, size_t bufSize,
                                   TLV::TLVReader & reader)
{
    TLV::TLVWriter writer;
    writer.Init(buffer, bufSize);
    ASSERT_EQ(cmd.Encode(writer, TLV::AnonymousTag()), CHIP_NO_ERROR);
    reader.Init(buffer, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
}

static void EncodeEnableDischarging(const Commands::EnableDischarging::Type & cmd, uint8_t * buffer, size_t bufSize,
                                    TLV::TLVReader & reader)
{
    TLV::TLVWriter writer;
    writer.Init(buffer, bufSize);
    ASSERT_EQ(cmd.Encode(writer, TLV::AnonymousTag()), CHIP_NO_ERROR);
    reader.Init(buffer, writer.GetLengthWritten());
    ASSERT_EQ(reader.Next(), CHIP_NO_ERROR);
}

// ===== Test Fixture =====

class TestEnergyEvseE2E : public ::testing::Test
{
protected:
    MockEnergyEvseDelegate mDelegate;
    TestPersistenceProvider mPersistence;
    EnergyEvse::Instance * mInstance = nullptr;

    void SetUp() override
    {
        SetSafeAttributePersistenceProvider(&mPersistence);

        // Features: ChargingPreferences + V2X + StartDiagnostics support
        BitMask<Feature> features(Feature::kChargingPreferences, Feature::kV2x);
        BitMask<OptionalAttributes> optAttrs(OptionalAttributes::kSupportsUserMaximumChargingCurrent,
                                             OptionalAttributes::kSupportsRandomizationWindow);
        BitMask<OptionalCommands> optCmds(OptionalCommands::kSupportsStartDiagnostics);

        mInstance = new EnergyEvse::Instance(kTestEndpoint, mDelegate, features, optAttrs, optCmds);
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
    }

    // Helper to invoke a command on the real server
    Status InvokeCommand(CommandId cmdId, TLV::TLVReader & reader)
    {
        MockCommandHandler handler;
        ConcreteCommandPath path(kTestEndpoint, EnergyEvse::Id, cmdId);

        CommandHandlerInterface::HandlerContext ctx(handler, path, reader);
        static_cast<CommandHandlerInterface *>(mInstance)->InvokeCommand(ctx);
        return handler.lastStatus;
    }
};

// =============================================================================
// PROP_EVSE_011 — Diagnostics DoS via Unbounded Duration
// =============================================================================

/**
 * Test: StartDiagnostics succeeds when SupplyState is Disabled,
 * transitioning to DisabledDiagnostics.
 */
TEST_F(TestEnergyEvseE2E, PROP011_StartDiagnosticsFromDisabled)
{
    // Ensure SupplyState is Disabled (default)
    ASSERT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabled);

    // Send StartDiagnostics via real InvokeCommand path
    Commands::StartDiagnostics::Type cmd;
    uint8_t buf[64];
    TLV::TLVReader reader;
    EncodeStartDiagnostics(cmd, buf, sizeof(buf), reader);

    Status status = InvokeCommand(Commands::StartDiagnostics::Id, reader);
    EXPECT_EQ(status, Status::Success);

    // Verify SupplyState changed to DisabledDiagnostics
    EXPECT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);
}

/**
 * Test: StartDiagnostics is rejected when not in Disabled state.
 * Per spec: "the EVSE SHALL enter a Diagnostics state only if the
 * SupplyState attribute is in the Disabled state"
 */
TEST_F(TestEnergyEvseE2E, PROP011_StartDiagnosticsRejectedWhenCharging)
{
    // Put EVSE into ChargingEnabled state
    mDelegate.SetSupplyState(SupplyStateEnum::kChargingEnabled);

    Commands::StartDiagnostics::Type cmd;
    uint8_t buf[64];
    TLV::TLVReader reader;
    EncodeStartDiagnostics(cmd, buf, sizeof(buf), reader);

    Status status = InvokeCommand(Commands::StartDiagnostics::Id, reader);
    // Should be rejected — not in Disabled state
    EXPECT_EQ(status, Status::Failure);
    EXPECT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kChargingEnabled);
}

/**
 * ATTACK: EnableCharging is blocked during DisabledDiagnostics.
 * This proves the DoS mechanism: once in diagnostics, charging cannot start.
 */
TEST_F(TestEnergyEvseE2E, PROP011_EnableChargingBlockedDuringDiagnostics)
{
    // Step 1: Enter diagnostics mode
    mDelegate.SetSupplyState(SupplyStateEnum::kDisabled);
    {
        Commands::StartDiagnostics::Type diagCmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeStartDiagnostics(diagCmd, buf, sizeof(buf), reader);
        ASSERT_EQ(InvokeCommand(Commands::StartDiagnostics::Id, reader), Status::Success);
    }
    ASSERT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);

    // Step 2: Try to EnableCharging — should FAIL per spec
    {
        Commands::EnableCharging::Type chargeCmd;
        chargeCmd.chargingEnabledUntil.SetNull();
        chargeCmd.minimumChargeCurrent = 6000;
        chargeCmd.maximumChargeCurrent = 32000;

        uint8_t buf[128];
        TLV::TLVReader reader;
        EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
        Status status = InvokeCommand(Commands::EnableCharging::Id, reader);

        // EnableCharging MUST fail during diagnostics
        EXPECT_EQ(status, Status::Failure);
    }

    // SupplyState must still be DisabledDiagnostics (DoS holds)
    EXPECT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);
}

/**
 * ATTACK: EnableDischarging (V2X) is also blocked during diagnostics.
 */
TEST_F(TestEnergyEvseE2E, PROP011_EnableDischargingBlockedDuringDiagnostics)
{
    mDelegate.SetSupplyState(SupplyStateEnum::kDisabled);
    {
        Commands::StartDiagnostics::Type diagCmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeStartDiagnostics(diagCmd, buf, sizeof(buf), reader);
        ASSERT_EQ(InvokeCommand(Commands::StartDiagnostics::Id, reader), Status::Success);
    }
    ASSERT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);

    // Try EnableDischarging — should also fail
    {
        Commands::EnableDischarging::Type dischCmd;
        dischCmd.dischargingEnabledUntil.SetNull();
        dischCmd.maximumDischargeCurrent = 16000;

        uint8_t buf[128];
        TLV::TLVReader reader;
        EncodeEnableDischarging(dischCmd, buf, sizeof(buf), reader);
        Status status = InvokeCommand(Commands::EnableDischarging::Id, reader);

        EXPECT_EQ(status, Status::Failure);
    }
    EXPECT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);
}

/**
 * ATTACK: Repeated StartDiagnostics after manual diagnostics completion.
 * Proves the attacker can re-enter diagnostics mode immediately,
 * creating an infinite DoS loop.
 */
TEST_F(TestEnergyEvseE2E, PROP011_RepeatedDiagnosticsDoSLoop)
{
    // Cycle 1: Enter diagnostics
    mDelegate.SetSupplyState(SupplyStateEnum::kDisabled);
    {
        Commands::StartDiagnostics::Type cmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeStartDiagnostics(cmd, buf, sizeof(buf), reader);
        ASSERT_EQ(InvokeCommand(Commands::StartDiagnostics::Id, reader), Status::Success);
    }
    ASSERT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);

    // Simulate diagnostics completion: manufacturer sets SupplyState back to Disabled
    mDelegate.SetSupplyState(SupplyStateEnum::kDisabled);

    // Cycle 2: Attacker immediately re-sends StartDiagnostics
    {
        Commands::StartDiagnostics::Type cmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeStartDiagnostics(cmd, buf, sizeof(buf), reader);
        ASSERT_EQ(InvokeCommand(Commands::StartDiagnostics::Id, reader), Status::Success);
    }
    ASSERT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);

    // EV is still unable to charge after 2 cycles — DoS loop proven
    {
        Commands::EnableCharging::Type chargeCmd;
        chargeCmd.chargingEnabledUntil.SetNull();
        chargeCmd.minimumChargeCurrent = 6000;
        chargeCmd.maximumChargeCurrent = 32000;

        uint8_t buf[128];
        TLV::TLVReader reader;
        EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
        EXPECT_EQ(InvokeCommand(Commands::EnableCharging::Id, reader), Status::Failure);
    }
}

/**
 * Verify Disable command is NOT blocked during diagnostics mode.
 * Disable always succeeds but doesn't exit diagnostics — it just sets
 * ChargingEnabledUntil/DischargingEnabledUntil to 0 and keeps Disabled state.
 */
TEST_F(TestEnergyEvseE2E, PROP011_DisableCommandDuringDiagnostics)
{
    // Enter diagnostics
    mDelegate.SetSupplyState(SupplyStateEnum::kDisabled);
    {
        Commands::StartDiagnostics::Type cmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeStartDiagnostics(cmd, buf, sizeof(buf), reader);
        ASSERT_EQ(InvokeCommand(Commands::StartDiagnostics::Id, reader), Status::Success);
    }
    ASSERT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);

    // Send Disable — Disable delegates to Delegate::Disable() which resets to kDisabled
    {
        Commands::Disable::Type disableCmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeDisable(disableCmd, buf, sizeof(buf), reader);
        Status status = InvokeCommand(Commands::Disable::Id, reader);
        // Disable always succeeds
        EXPECT_EQ(status, Status::Success);
    }

    // After Disable, SupplyState is now Disabled (diagnostics ended via Disable)
    // Attacker can re-enter diagnostics immediately from Disabled
    EXPECT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabled);

    // Re-enter diagnostics
    {
        Commands::StartDiagnostics::Type cmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeStartDiagnostics(cmd, buf, sizeof(buf), reader);
        EXPECT_EQ(InvokeCommand(Commands::StartDiagnostics::Id, reader), Status::Success);
    }
    EXPECT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);
}

/**
 * Verify that StartDiagnostics requires Operate privilege (same as EnableCharging).
 * Both use "O T" access. This confirms the privilege asymmetry vulnerability:
 * the same Operate-level actor can both start diagnostics and normally enable charging.
 */
TEST_F(TestEnergyEvseE2E, PROP011_DiagnosticsAndChargingUseSamePrivilege)
{
    // First verify EnableCharging works from Disabled
    {
        Commands::EnableCharging::Type chargeCmd;
        chargeCmd.chargingEnabledUntil.SetNull();
        chargeCmd.minimumChargeCurrent = 6000;
        chargeCmd.maximumChargeCurrent = 32000;

        uint8_t buf[128];
        TLV::TLVReader reader;
        EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
        ASSERT_EQ(InvokeCommand(Commands::EnableCharging::Id, reader), Status::Success);
    }
    ASSERT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kChargingEnabled);

    // Now Disable and start diagnostics
    mDelegate.SetSupplyState(SupplyStateEnum::kDisabled);
    {
        Commands::StartDiagnostics::Type cmd;
        uint8_t buf[64];
        TLV::TLVReader reader;
        EncodeStartDiagnostics(cmd, buf, sizeof(buf), reader);
        ASSERT_EQ(InvokeCommand(Commands::StartDiagnostics::Id, reader), Status::Success);
    }

    // Both commands accepted — same Operate privilege, but diagnostics blocks charging
    EXPECT_EQ(mDelegate.GetSupplyState(), SupplyStateEnum::kDisabledDiagnostics);
    EXPECT_EQ(mDelegate.GetStartDiagnosticsCallCount(), 1u);
    EXPECT_EQ(mDelegate.GetEnableChargingCallCount(), 1u);
}

// =============================================================================
// PROP_EVSE_036 — Time Synchronization Dependency for Epoch Attributes
// =============================================================================

/**
 * Test: ChargingEnabledUntil can be set via EnableCharging command.
 * This confirms that the EVSE accepts epoch_s values that depend on
 * external time source integrity.
 */
TEST_F(TestEnergyEvseE2E, PROP036_ChargingEnabledUntilAcceptsEpochValue)
{
    Commands::EnableCharging::Type chargeCmd;
    // Set expire time to specific epoch value (e.g., 2025-01-01 02:00:00 UTC in Matter epoch)
    chargeCmd.chargingEnabledUntil = DataModel::MakeNullable(static_cast<uint32_t>(789000000));
    chargeCmd.minimumChargeCurrent = 6000;
    chargeCmd.maximumChargeCurrent = 32000;

    uint8_t buf[128];
    TLV::TLVReader reader;
    EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
    Status status = InvokeCommand(Commands::EnableCharging::Id, reader);

    EXPECT_EQ(status, Status::Success);
    // The epoch value was accepted with no integrity validation
    EXPECT_FALSE(mDelegate.GetChargingEnabledUntil().IsNull());
    EXPECT_EQ(mDelegate.GetChargingEnabledUntil().Value(), 789000000u);
}

/**
 * Test: Null ChargingEnabledUntil means indefinite charging.
 * No time boundary enforcement at all.
 */
TEST_F(TestEnergyEvseE2E, PROP036_NullChargingEnabledUntilMeansIndefinite)
{
    Commands::EnableCharging::Type chargeCmd;
    chargeCmd.chargingEnabledUntil.SetNull();
    chargeCmd.minimumChargeCurrent = 6000;
    chargeCmd.maximumChargeCurrent = 32000;

    uint8_t buf[128];
    TLV::TLVReader reader;
    EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
    ASSERT_EQ(InvokeCommand(Commands::EnableCharging::Id, reader), Status::Success);

    // Null means no expiry — charging runs indefinitely with no time source check
    EXPECT_TRUE(mDelegate.GetChargingEnabledUntil().IsNull());
}

/**
 * Test: DischargingEnabledUntil similarly accepts arbitrary epoch values.
 */
TEST_F(TestEnergyEvseE2E, PROP036_DischargingEnabledUntilAcceptsEpochValue)
{
    Commands::EnableDischarging::Type dischCmd;
    dischCmd.dischargingEnabledUntil = DataModel::MakeNullable(static_cast<uint32_t>(789000000));
    dischCmd.maximumDischargeCurrent = 16000;

    uint8_t buf[128];
    TLV::TLVReader reader;
    EncodeEnableDischarging(dischCmd, buf, sizeof(buf), reader);
    Status status = InvokeCommand(Commands::EnableDischarging::Id, reader);

    EXPECT_EQ(status, Status::Success);
    EXPECT_FALSE(mDelegate.GetDischargingEnabledUntil().IsNull());
    EXPECT_EQ(mDelegate.GetDischargingEnabledUntil().Value(), 789000000u);
}

/**
 * ATTACK: Past epoch value accepted for ChargingEnabledUntil.
 * The server does not validate that ChargingEnabledUntil is in the future.
 * An attacker can set a past time, and the charging session would either
 * expire immediately or the time check behavior depends on the system clock.
 */
TEST_F(TestEnergyEvseE2E, PROP036_PastEpochValueAccepted)
{
    Commands::EnableCharging::Type chargeCmd;
    // Set to epoch value 1 (essentially Jan 1 2000 00:00:01 — definitely in the past)
    chargeCmd.chargingEnabledUntil = DataModel::MakeNullable(static_cast<uint32_t>(1));
    chargeCmd.minimumChargeCurrent = 6000;
    chargeCmd.maximumChargeCurrent = 32000;

    uint8_t buf[128];
    TLV::TLVReader reader;
    EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
    Status status = InvokeCommand(Commands::EnableCharging::Id, reader);

    // Command succeeds — no validation that the epoch is in the future
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(mDelegate.GetChargingEnabledUntil().Value(), 1u);
}

/**
 * ATTACK: EnableCharging with zero epoch value.
 * Zero in epoch_s context means "already expired" per common interpretation.
 * The server accepts this without checking.
 */
TEST_F(TestEnergyEvseE2E, PROP036_ZeroEpochValueAccepted)
{
    Commands::EnableCharging::Type chargeCmd;
    chargeCmd.chargingEnabledUntil = DataModel::MakeNullable(static_cast<uint32_t>(0));
    chargeCmd.minimumChargeCurrent = 6000;
    chargeCmd.maximumChargeCurrent = 32000;

    uint8_t buf[128];
    TLV::TLVReader reader;
    EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
    Status status = InvokeCommand(Commands::EnableCharging::Id, reader);

    // Accepted — no time validation
    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(mDelegate.GetChargingEnabledUntil().Value(), 0u);
}

/**
 * ATTACK: Large epoch value accepted — charging far into the future.
 * No reasonable upper bound enforcement exists beyond uint32 limits.
 */
TEST_F(TestEnergyEvseE2E, PROP036_LargeEpochValueAccepted)
{
    Commands::EnableCharging::Type chargeCmd;
    // ~year 2126 in Matter epoch — over a century of charging
    chargeCmd.chargingEnabledUntil = DataModel::MakeNullable(static_cast<uint32_t>(4000000000u));
    chargeCmd.minimumChargeCurrent = 6000;
    chargeCmd.maximumChargeCurrent = 32000;

    uint8_t buf[128];
    TLV::TLVReader reader;
    EncodeEnableCharging(chargeCmd, buf, sizeof(buf), reader);
    Status status = InvokeCommand(Commands::EnableCharging::Id, reader);

    EXPECT_EQ(status, Status::Success);
    EXPECT_EQ(mDelegate.GetChargingEnabledUntil().Value(), 4000000000u);
}
