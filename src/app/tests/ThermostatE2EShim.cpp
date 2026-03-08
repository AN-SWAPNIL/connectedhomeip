/**
 * @file ThermostatE2EShim.cpp
 *
 * Self-contained in-memory attribute shim for Thermostat cluster (0x0201) tests.
 * Provides:
 *   - In-memory attribute storage (std::map-backed)
 *   - All emberAf read/write functions the generated Accessors need
 *   - Endpoint stubs
 *   - The PreAttributeChangedCallback extracted from thermostat-server.cpp
 *
 * This file intentionally does NOT depend on mock_ember or mock_codegen_data_model.
 */

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/cluster-objects.h>
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/ConcreteAttributePath.h>
#include <app/util/af-types.h>
#include <app/util/attribute-metadata.h>
#include <app/util/attribute-table.h>
#include <lib/core/CHIPEncoding.h>
#include <lib/core/DataModelTypes.h>
#include <protocols/interaction_model/StatusCode.h>

#include <cstring>
#include <map>
#include <vector>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters::Thermostat;
using namespace chip::app::Clusters::Thermostat::Attributes;
using Status = Protocols::InteractionModel::Status;

// Forward declarations for internal functions (normally from attribute-storage-detail.h)
// We avoid including that header because it pulls in zap-generated/gen_config.h
Status emAfReadOrWriteAttribute(const EmberAfAttributeSearchRecord * attRecord, const EmberAfAttributeMetadata ** metadata,
                                uint8_t * buffer, uint16_t readLength, bool write);
Status emAfWriteAttributeExternal(const ConcreteAttributePath & path, const EmberAfWriteDataInput & input);

// ============================================================================
// In-memory attribute storage
// ============================================================================

namespace {

struct AttrKey
{
    EndpointId endpoint;
    ClusterId cluster;
    AttributeId attribute;
    bool operator<(const AttrKey & o) const
    {
        if (endpoint != o.endpoint)
            return endpoint < o.endpoint;
        if (cluster != o.cluster)
            return cluster < o.cluster;
        return attribute < o.attribute;
    }
};

std::map<AttrKey, std::vector<uint8_t>> gAttrStore;

uint16_t SizeForType(EmberAfAttributeType type)
{
    switch (type)
    {
    case 0x20:
    case 0x28:
    case 0x30:
    case 0x18:
        return 1; // uint8/int8/enum8/bitmap8
    case 0x21:
    case 0x29:
    case 0x31:
    case 0x19:
        return 2; // uint16/int16/enum16/bitmap16
    case 0x22:
    case 0x2A:
        return 3; // uint24/int24
    case 0x23:
    case 0x2B:
    case 0xE2:
    case 0x1B:
        return 4; // uint32/int32/epoch_s/bitmap32
    case 0x24:
    case 0x2C:
        return 5; // uint40/int40
    case 0x25:
    case 0x2D:
        return 6; // uint48/int48
    case 0x26:
    case 0x2E:
        return 7; // uint56/int56
    case 0x27:
    case 0x2F:
    case 0xE3:
        return 8; // uint64/int64/epoch_us
    default:
        return 4;
    }
}

} // namespace

// ============================================================================
// Core internal function — used by attribute-storage.cpp if linked.
// We provide it so that anything calling emAfReadOrWriteAttribute is satisfied.
// ============================================================================

Status emAfReadOrWriteAttribute(const EmberAfAttributeSearchRecord * attRecord, const EmberAfAttributeMetadata ** metadata,
                                uint8_t * buffer, uint16_t readLength, bool write)
{
    AttrKey key{ attRecord->endpoint, attRecord->clusterId, attRecord->attributeId };

    if (write)
    {
        auto & vec = gAttrStore[key];
        if (vec.empty())
            vec.resize(readLength > 0 ? readLength : 4);
        uint16_t copyLen = std::min(readLength, static_cast<uint16_t>(vec.size()));
        std::memcpy(vec.data(), buffer, copyLen);
    }
    else
    {
        auto it = gAttrStore.find(key);
        if (it == gAttrStore.end())
            std::memset(buffer, 0, readLength);
        else
        {
            uint16_t copyLen = std::min(readLength, static_cast<uint16_t>(it->second.size()));
            std::memcpy(buffer, it->second.data(), copyLen);
            if (copyLen < readLength)
                std::memset(buffer + copyLen, 0, readLength - copyLen);
        }
    }
    return Status::Success;
}

// ============================================================================
// External write path
// ============================================================================

Status emAfWriteAttributeExternal(const ConcreteAttributePath & path, const EmberAfWriteDataInput & input)
{
    uint16_t sz = SizeForType(input.dataType);
    AttrKey key{ path.mEndpointId, path.mClusterId, path.mAttributeId };
    auto & vec = gAttrStore[key];
    vec.resize(sz);
    std::memcpy(vec.data(), input.dataPtr, sz);
    return Status::Success;
}

// ============================================================================
// Public API — called by generated Accessors.cpp
// ============================================================================

// 5-arg overload: used by Accessors::Set(endpoint, value)
Status emberAfWriteAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr,
                             EmberAfAttributeType dataType)
{
    return emAfWriteAttributeExternal(ConcreteAttributePath(endpoint, cluster, attributeID),
                                      EmberAfWriteDataInput(dataPtr, dataType));
}

// 2-arg overload: used by Accessors::Set(endpoint, value, markDirty)
Status emberAfWriteAttribute(const ConcreteAttributePath & path, const EmberAfWriteDataInput & input)
{
    return emAfWriteAttributeExternal(path, input);
}

// Read: used by Accessors::Get(endpoint, &value)
Status emberAfReadAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr, uint16_t readLength)
{
    AttrKey key{ endpoint, cluster, attributeID };
    auto it = gAttrStore.find(key);
    if (it == gAttrStore.end())
    {
        std::memset(dataPtr, 0, readLength);
    }
    else
    {
        uint16_t copyLen = std::min(readLength, static_cast<uint16_t>(it->second.size()));
        std::memcpy(dataPtr, it->second.data(), copyLen);
        if (copyLen < readLength)
            std::memset(dataPtr + copyLen, 0, readLength - copyLen);
    }
    return Status::Success;
}

// ============================================================================
// Reporting stub
// ============================================================================

void MatterReportingAttributeChangeCallback(EndpointId, ClusterId, AttributeId) {}
void MatterReportingAttributeChangeCallback(const ConcreteAttributePath &) {}
void MatterReportingAttributeChangeCallback(EndpointId) {}

// ============================================================================
// Endpoint stubs
// ============================================================================

uint16_t emberAfGetClusterServerEndpointIndex(EndpointId endpoint, ClusterId cluster, uint16_t fixedClusterServerEndpointCount)
{
    return (endpoint == 0) ? 0 : 0xFFFF;
}

uint16_t emberAfEndpointCount()
{
    return 1;
}

EndpointId emberAfEndpointFromIndex(uint16_t index)
{
    return (index == 0) ? static_cast<EndpointId>(0) : kInvalidEndpointId;
}

uint16_t emberAfIndexFromEndpoint(EndpointId endpoint)
{
    return (endpoint == 0) ? 0 : 0xFFFF;
}

bool emberAfContainsServer(EndpointId endpoint, ClusterId clusterId)
{
    return (endpoint == 0 && clusterId == Clusters::Thermostat::Id);
}

// ============================================================================
// Public helper: clear all stored attributes (for test isolation)
// ============================================================================

void ThermostatShimClearAll()
{
    gAttrStore.clear();
}

// ============================================================================
// MatterThermostatClusterServerPreAttributeChangedCallback
// (Extracted verbatim from thermostat-server.cpp — the REAL validation logic
//  that our spec-gap tests exercise.)
// ============================================================================

static constexpr int16_t kDefaultAbsMinHeat = 700;  // 7.0 °C
static constexpr int16_t kDefaultAbsMaxHeat = 3000; // 30.0 °C
static constexpr int16_t kDefaultAbsMinCool = 1600; // 16.0 °C
static constexpr int16_t kDefaultAbsMaxCool = 3200; // 32.0 °C
static constexpr int8_t kDefaultDeadBand    = 25;   // 2.5 °C

Status MatterThermostatClusterServerPreAttributeChangedCallback(const ConcreteAttributePath & attributePath,
                                                                EmberAfAttributeType attributeType, uint16_t size, uint8_t * value)
{
    EndpointId ep = attributePath.mEndpointId;
    int16_t requested;

    // Read limits & feature map
    int16_t absMinHeat, absMaxHeat, minHeat, maxHeat;
    int16_t absMinCool, absMaxCool, minCool, maxCool;
    int8_t deadBand = 0;
    int16_t occCool, occHeat;
    uint32_t featureMap;
    bool autoOn = false, heatOn = false, coolOn = false;

    if (FeatureMap::Get(ep, &featureMap) != Status::Success)
        featureMap = 0x23; // HEAT|COOL|AUTO

    if (featureMap & 0x20)
        autoOn = true;
    if (featureMap & 0x01)
        heatOn = true;
    if (featureMap & 0x02)
        coolOn = true;

    if (autoOn)
    {
        if (MinSetpointDeadBand::Get(ep, &deadBand) != Status::Success)
            deadBand = kDefaultDeadBand;
    }

    if (AbsMinCoolSetpointLimit::Get(ep, &absMinCool) != Status::Success)
        absMinCool = kDefaultAbsMinCool;
    if (AbsMaxCoolSetpointLimit::Get(ep, &absMaxCool) != Status::Success)
        absMaxCool = kDefaultAbsMaxCool;
    if (MinCoolSetpointLimit::Get(ep, &minCool) != Status::Success)
        minCool = absMinCool;
    if (MaxCoolSetpointLimit::Get(ep, &maxCool) != Status::Success)
        maxCool = absMaxCool;

    if (AbsMinHeatSetpointLimit::Get(ep, &absMinHeat) != Status::Success)
        absMinHeat = kDefaultAbsMinHeat;
    if (AbsMaxHeatSetpointLimit::Get(ep, &absMaxHeat) != Status::Success)
        absMaxHeat = kDefaultAbsMaxHeat;
    if (MinHeatSetpointLimit::Get(ep, &minHeat) != Status::Success)
        minHeat = absMinHeat;
    if (MaxHeatSetpointLimit::Get(ep, &maxHeat) != Status::Success)
        maxHeat = absMaxHeat;

    if (coolOn)
        if (OccupiedCoolingSetpoint::Get(ep, &occCool) != Status::Success)
            return Status::Failure;

    if (heatOn)
        if (OccupiedHeatingSetpoint::Get(ep, &occHeat) != Status::Success)
            return Status::Failure;

    switch (attributePath.mAttributeId)
    {
    case OccupiedHeatingSetpoint::Id: {
        requested = static_cast<int16_t>(chip::Encoding::LittleEndian::Get16(value));
        if (!heatOn)
            return Status::UnsupportedAttribute;
        if (requested < absMinHeat || requested < minHeat || requested > absMaxHeat || requested > maxHeat)
            return Status::InvalidValue;
        return Status::Success;
    }
    case OccupiedCoolingSetpoint::Id: {
        requested = static_cast<int16_t>(chip::Encoding::LittleEndian::Get16(value));
        if (!coolOn)
            return Status::UnsupportedAttribute;
        if (requested < absMinCool || requested < minCool || requested > absMaxCool || requested > maxCool)
            return Status::InvalidValue;
        return Status::Success;
    }
    case MinSetpointDeadBand::Id: {
        requested = *value;
        if (!autoOn)
            return Status::UnsupportedAttribute;
        if (requested < 0 || requested > 127)
            return Status::InvalidValue;
        return Status::Success;
    }
    default:
        // *** THIS IS THE SPEC GAP ***
        // EmergencyHeatDelta, LocalTemperatureCalibration, SetpointChangeSource,
        // TemperatureSetpointHold, etc. — ALL fall through here with no validation.
        return Status::Success;
    }
}

// Stub init
void emberAfThermostatClusterServerInitCallback(EndpointId) {}
