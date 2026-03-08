/**
 * Minimal shim providing missing symbols for Smoke CO Alarm E2E tests.
 * Provides in-memory attribute storage so Get/Set actually persist values.
 */

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

// In-memory attribute storage: key = (endpoint, cluster, attribute) → value bytes
static std::map<std::tuple<EndpointId, ClusterId, AttributeId>, std::vector<uint8_t>> sAttributeStore;

// Call this between tests to reset attribute state
void ResetTestAttributeStore()
{
    sAttributeStore.clear();
}

// emberAfReadAttribute: reads from in-memory storage (zeroed if not yet written)
Status emberAfReadAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr, uint16_t readLength)
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

// Stub: attribute change listener
chip::app::DataModel::ProviderChangeListener * emberAfGlobalInteractionModelAttributesChangedListener()
{
    return nullptr;
}

// 5-argument legacy write — stores to in-memory map
Status emberAfWriteAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr,
                             EmberAfAttributeType dataType)
{
    auto key = std::make_tuple(endpoint, cluster, attributeID);
    // Infer size from dataType (most smoke-co-alarm attrs are 1-byte enums or booleans)
    uint16_t len = 1;
    switch (dataType)
    {
    case ZCL_INT16U_ATTRIBUTE_TYPE:
    case ZCL_INT16S_ATTRIBUTE_TYPE:
        len = 2;
        break;
    case ZCL_INT32U_ATTRIBUTE_TYPE:
    case ZCL_INT32S_ATTRIBUTE_TYPE:
    case ZCL_EPOCH_S_ATTRIBUTE_TYPE:
    case ZCL_BITMAP32_ATTRIBUTE_TYPE:
        len = 4;
        break;
    default:
        len = 1;
        break;
    }
    sAttributeStore[key].assign(dataPtr, dataPtr + len);
    return Status::Success;
}

// Stubs for protocol name lookups
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
