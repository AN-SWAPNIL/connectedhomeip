/**
 * In-memory attribute storage shim for Window Covering tests.
 *
 * Mirrors the pattern used by SmokeCoAlarmE2EShim / ContentControlE2EShim:
 * a std::map keyed by (endpoint, cluster, attribute) stores raw bytes so that
 * the generated Accessors Get/Set helpers work without a real attribute store.
 */

#include "window_covering_attr_shim.h"

#include <app/ConcreteAttributePath.h>
#include <app/util/MarkAttributeDirty.h>
#include <app/util/attribute-storage-detail.h>
#include <app/util/attribute-storage.h>
#include <app/util/attribute-table.h>
#include <lib/core/CHIPError.h>
#include <protocols/Protocols.h>

#include <cstring>
#include <map>
#include <tuple>
#include <vector>

using chip::AttributeId;
using chip::ClusterId;
using chip::EndpointId;
using chip::Protocols::InteractionModel::Status;

// Key = (endpoint, cluster, attribute), value = raw bytes
static std::map<std::tuple<EndpointId, ClusterId, AttributeId>, std::vector<uint8_t>> sAttributeStore;

void WindowCoveringTestShim::Reset()
{
    sAttributeStore.clear();
}

// ---------------------------------------------------------------------------
// emberAfReadAttribute — reads from in-memory map (zeroed if unwritten)
// ---------------------------------------------------------------------------
Status emberAfReadAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr,
                            uint16_t readLength)
{
    auto key = std::make_tuple(endpoint, cluster, attributeID);
    auto it  = sAttributeStore.find(key);
    if (it != sAttributeStore.end())
    {
        size_t copyLen = std::min(static_cast<size_t>(readLength), it->second.size());
        memcpy(dataPtr, it->second.data(), copyLen);
        if (copyLen < readLength)
            memset(dataPtr + copyLen, 0, readLength - copyLen);
    }
    else
    {
        memset(dataPtr, 0, readLength);
    }
    return Status::Success;
}

// ---------------------------------------------------------------------------
// emberAfWriteAttribute (ConcreteAttributePath overload — used by MarkDirty path)
// ---------------------------------------------------------------------------
Status emberAfWriteAttribute(const chip::app::ConcreteAttributePath & path, const EmberAfWriteDataInput & input)
{
    auto key = std::make_tuple(path.mEndpointId, path.mClusterId, path.mAttributeId);
    // Determine size from data type
    uint16_t len = 2; // default: Percent100ths = uint16
    switch (input.dataType)
    {
    case ZCL_INT8U_ATTRIBUTE_TYPE:
    case ZCL_INT8S_ATTRIBUTE_TYPE:
    case ZCL_BOOLEAN_ATTRIBUTE_TYPE:
    case ZCL_ENUM8_ATTRIBUTE_TYPE:
    case ZCL_BITMAP8_ATTRIBUTE_TYPE:
        len = 1;
        break;
    case ZCL_INT16U_ATTRIBUTE_TYPE:
    case ZCL_INT16S_ATTRIBUTE_TYPE:
    case ZCL_PERCENT100THS_ATTRIBUTE_TYPE:
        len = 2;
        break;
    case ZCL_INT32U_ATTRIBUTE_TYPE:
    case ZCL_INT32S_ATTRIBUTE_TYPE:
    case ZCL_EPOCH_S_ATTRIBUTE_TYPE:
    case ZCL_BITMAP32_ATTRIBUTE_TYPE:
        len = 4;
        break;
    default:
        len = 2;
        break;
    }
    sAttributeStore[key].assign(input.dataPtr, input.dataPtr + len);
    return Status::Success;
}

// ---------------------------------------------------------------------------
// emberAfWriteAttribute (5-arg legacy overload)
// ---------------------------------------------------------------------------
Status emberAfWriteAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr,
                             EmberAfAttributeType dataType)
{
    EmberAfWriteDataInput input(dataPtr, dataType);
    return emberAfWriteAttribute(chip::app::ConcreteAttributePath(endpoint, cluster, attributeID), input);
}

// ---------------------------------------------------------------------------
// Required stubs
// ---------------------------------------------------------------------------
chip::app::DataModel::ProviderChangeListener * emberAfGlobalInteractionModelAttributesChangedListener()
{
    return nullptr;
}

namespace chip {
namespace Protocols {

const char * GetProtocolName(Id protocolId)
{
    return "test";
}

const char * GetMessageTypeName(Id protocolId, uint8_t msgType)
{
    return "test-msg";
}

} // namespace Protocols
} // namespace chip
