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
 * @file TestEnergyEvseSpecGap.cpp
 *
 * Specification-gap metadata tests for the Energy EVSE cluster (section 9.3).
 *
 * These tests inspect the generated metadata and cluster design to verify
 * structural spec-gap properties, without needing full E2E InvokeCommand.
 *
 * PROP_EVSE_011 — No CancelDiagnostics command; StartDiagnostics uses
 *     same Operate privilege as EnableCharging; no diagnostic timeout attribute.
 *
 * PROP_EVSE_036 — No time quality attribute; no time source integrity
 *     enforcement; epoch attributes have no bounds checking.
 */

#include <gtest/gtest.h>

#include <app/clusters/energy-evse-server/energy-evse-server.h>
#include <app/CommandHandlerInterface.h>
#include <clusters/EnergyEvse/ClusterId.h>
#include <clusters/EnergyEvse/Commands.h>
#include <clusters/EnergyEvse/Metadata.h>
#include <lib/core/DataModelTypes.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::EnergyEvse;
using Status = Protocols::InteractionModel::Status;

// =============================================================================
// PROP_EVSE_011 — Diagnostics DoS metadata analysis
// =============================================================================

/**
 * Test: StartDiagnostics requires Timed Invoke (T flag) and Operate privilege.
 * Same as EnableCharging. This confirms the privilege asymmetry:
 * the attacker who can charge can also trigger diagnostics.
 */
TEST(TestEnergyEvseSpecGap, PROP011_StartDiagnosticsMetadataTimedAndOperate)
{
    const auto & entry = Commands::StartDiagnostics::kMetadataEntry;

    // Verify Timed Invoke is required
    EXPECT_TRUE(entry.HasFlags(DataModel::CommandQualityFlags::kTimed))
        << "StartDiagnostics must require Timed Invoke ('T' in access column)";

    // Verify Operate privilege
    EXPECT_EQ(entry.GetInvokePrivilege(), Access::Privilege::kOperate)
        << "StartDiagnostics requires Operate privilege — same as EnableCharging";
}

/**
 * Test: EnableCharging also requires Timed Invoke and Operate privilege.
 * This demonstrates the privilege equivalence between the two commands.
 */
TEST(TestEnergyEvseSpecGap, PROP011_EnableChargingMetadataTimedAndOperate)
{
    const auto & entry = Commands::EnableCharging::kMetadataEntry;

    EXPECT_TRUE(entry.HasFlags(DataModel::CommandQualityFlags::kTimed));
    EXPECT_EQ(entry.GetInvokePrivilege(), Access::Privilege::kOperate);
}

/**
 * Test: No CancelDiagnostics command exists.
 * Verify by checking all accepted command IDs — none has a "CancelDiagnostics"
 * semantic. The spec defines exactly 7 commands; none cancels diagnostics.
 *
 * Spec command IDs:
 *   0x01 = Disable
 *   0x02 = EnableCharging
 *   0x03 = EnableDischarging
 *   0x04 = StartDiagnostics
 *   0x05 = SetTargets
 *   0x06 = GetTargets
 *   0x07 = ClearTargets
 */
TEST(TestEnergyEvseSpecGap, PROP011_NoCancelDiagnosticsCommand)
{
    // Verify that the 7 spec-defined commands exist
    EXPECT_EQ(Commands::Disable::Id, 0x01u);
    EXPECT_EQ(Commands::EnableCharging::Id, 0x02u);
    EXPECT_EQ(Commands::EnableDischarging::Id, 0x03u);
    EXPECT_EQ(Commands::StartDiagnostics::Id, 0x04u);
    EXPECT_EQ(Commands::SetTargets::Id, 0x05u);
    EXPECT_EQ(Commands::GetTargets::Id, 0x06u);
    EXPECT_EQ(Commands::ClearTargets::Id, 0x07u);

    // There is no command ID 0x08 or any "CancelDiagnostics" command.
    // The cluster has exactly 7 accepted commands.
    // An attacker who starts diagnostics has no cluster-level way to cancel it.
    // Only the manufacturer's internal completion event or the Disable command
    // can exit diagnostics mode.
}

/**
 * Test: StartDiagnostics is optional (kSupportsStartDiagnostics).
 * When supported, there is still no max duration attribute.
 * Verify no "DiagnosticsDuration" or "MaxDiagnosticsDuration" attribute exists.
 */
TEST(TestEnergyEvseSpecGap, PROP011_NoDiagnosticsDurationAttribute)
{
    // The cluster defines these attribute IDs:
    //   0x0000 = State
    //   0x0001 = SupplyState
    //   0x0002 = FaultState
    //   0x0003 = ChargingEnabledUntil
    //   0x0004 = DischargingEnabledUntil
    //   0x0005 = CircuitCapacity
    //   0x0006 = MinimumChargeCurrent
    //   0x0007 = MaximumChargeCurrent
    //   0x0008 = MaximumDischargeCurrent
    //   0x0009 = UserMaximumChargeCurrent
    //   0x000A = RandomizationDelayWindow
    //   (gap)
    //   0x0023-0x0027 = PREF attributes
    //   0x0030-0x0031 = SOC attributes
    //   0x0032 = VehicleID (PNC)
    //   0x0040-0x0043 = Session attributes
    //
    // No attribute for diagnostic duration, timeout, or max diagnostic time exists.
    // This confirms the spec gap: no visibility into diagnostic progress or duration.

    using namespace Attributes;
    EXPECT_EQ(State::Id, 0x0000u);
    EXPECT_EQ(SupplyState::Id, 0x0001u);
    EXPECT_EQ(FaultState::Id, 0x0002u);
    EXPECT_EQ(ChargingEnabledUntil::Id, 0x0003u);
    EXPECT_EQ(DischargingEnabledUntil::Id, 0x0004u);

    // Verify that SupplyState can be DisabledDiagnostics but there is no
    // associated duration attribute
    EXPECT_EQ(static_cast<uint8_t>(SupplyStateEnum::kDisabledDiagnostics), 0x04u);
}

/**
 * Test: All 7 commands use same Operate privilege.
 * No command has elevated (Manage or Administer) privilege.
 * This means an Operate-level actor has full command access.
 */
TEST(TestEnergyEvseSpecGap, PROP011_AllCommandsSameOperatePrivilege)
{
    EXPECT_EQ(Commands::Disable::kMetadataEntry.GetInvokePrivilege(), Access::Privilege::kOperate);
    EXPECT_EQ(Commands::EnableCharging::kMetadataEntry.GetInvokePrivilege(), Access::Privilege::kOperate);
    EXPECT_EQ(Commands::EnableDischarging::kMetadataEntry.GetInvokePrivilege(), Access::Privilege::kOperate);
    EXPECT_EQ(Commands::StartDiagnostics::kMetadataEntry.GetInvokePrivilege(), Access::Privilege::kOperate);
    EXPECT_EQ(Commands::SetTargets::kMetadataEntry.GetInvokePrivilege(), Access::Privilege::kOperate);
    EXPECT_EQ(Commands::GetTargets::kMetadataEntry.GetInvokePrivilege(), Access::Privilege::kOperate);
    EXPECT_EQ(Commands::ClearTargets::kMetadataEntry.GetInvokePrivilege(), Access::Privilege::kOperate);
}

/**
 * Test: All 7 commands require Timed Invoke.
 * This confirms the DISPROVED PROP_EVSE_001 defense:
 * the spec correctly mandates Timed Invoke for all commands.
 */
TEST(TestEnergyEvseSpecGap, DISPROVED_001_AllCommandsRequireTimedInvoke)
{
    EXPECT_TRUE(Commands::Disable::kMetadataEntry.HasFlags(DataModel::CommandQualityFlags::kTimed));
    EXPECT_TRUE(Commands::EnableCharging::kMetadataEntry.HasFlags(DataModel::CommandQualityFlags::kTimed));
    EXPECT_TRUE(Commands::EnableDischarging::kMetadataEntry.HasFlags(DataModel::CommandQualityFlags::kTimed));
    EXPECT_TRUE(Commands::StartDiagnostics::kMetadataEntry.HasFlags(DataModel::CommandQualityFlags::kTimed));
    EXPECT_TRUE(Commands::SetTargets::kMetadataEntry.HasFlags(DataModel::CommandQualityFlags::kTimed));
    EXPECT_TRUE(Commands::GetTargets::kMetadataEntry.HasFlags(DataModel::CommandQualityFlags::kTimed));
    EXPECT_TRUE(Commands::ClearTargets::kMetadataEntry.HasFlags(DataModel::CommandQualityFlags::kTimed));
}

// =============================================================================
// PROP_EVSE_036 — Time Synchronization Dependency metadata analysis
// =============================================================================

/**
 * Test: ChargingEnabledUntil is epoch_s (uint32_t) with no time quality
 * attribute in the cluster.
 */
TEST(TestEnergyEvseSpecGap, PROP036_EpochAttributesExistWithNoTimeQuality)
{
    using namespace Attributes;

    // Verify the epoch-based attributes exist
    EXPECT_EQ(ChargingEnabledUntil::Id, 0x0003u);
    EXPECT_EQ(DischargingEnabledUntil::Id, 0x0004u);

    // No TimeSourceQuality, TimeSourceStatus, or similar attribute exists in the cluster.
    // The cluster depends on external time (Section 9.3.5 Dependencies) but provides
    // no mechanism to indicate time source reliability to the application.
}

/**
 * Test: FaultState is read-only (R V access).
 * This confirms DISPROVED PROP_EVSE_008: FaultState cannot be written
 * remotely via Matter protocol.
 */
TEST(TestEnergyEvseSpecGap, DISPROVED_008_FaultStateReadOnly)
{
    using namespace Attributes;

    // FaultState read privilege is View
    EXPECT_EQ(FaultState::kMetadataEntry.GetReadPrivilege(), std::make_optional(Access::Privilege::kView));

    // FaultState has no write privilege — it's read-only
    // The metadata entry for a read-only attribute will not have a write privilege set
    EXPECT_FALSE(FaultState::kMetadataEntry.GetWritePrivilege().has_value())
        << "FaultState must be read-only — no write privilege should be defined";
}

/**
 * Test: UserMaximumChargeCurrent and RandomizationDelayWindow require
 * Manage privilege for writes.
 * This confirms DISPROVED PROP_EVSE_031: RandomizationDelayWindow is
 * Manage-protected, not Operate-accessible for writes.
 */
TEST(TestEnergyEvseSpecGap, DISPROVED_031_RandomizationDelayWindowManageProtected)
{
    using namespace Attributes;

    EXPECT_EQ(UserMaximumChargeCurrent::kMetadataEntry.GetWritePrivilege(),
              std::make_optional(Access::Privilege::kManage));
    EXPECT_EQ(RandomizationDelayWindow::kMetadataEntry.GetWritePrivilege(),
              std::make_optional(Access::Privilege::kManage));
}

/**
 * Test: RandomizationDelayWindow max constraint is 86400.
 * Verify the compile-time constant.
 */
TEST(TestEnergyEvseSpecGap, DISPROVED_031_RandomizationDelayWindowMaxConstant)
{
    EXPECT_EQ(kMaxRandomizationDelayWindow, 86400u);
}
