/**
 * Minimal shim providing missing symbols for Door Lock E2E tests.
 * Bridges the gap between CodegenEmberMocks (which provides emAfReadOrWriteAttribute
 * but not emberAfReadAttribute) and Accessors.cpp (which calls emberAfReadAttribute).
 * Also stubs protocol name lookups and the global attribute change listener.
 */

#include <app/util/MarkAttributeDirty.h>
#include <app/util/attribute-storage-detail.h>
#include <app/util/attribute-storage.h>
#include <app/util/attribute-table.h>
#include <lib/core/CHIPError.h>
#include <protocols/Protocols.h>

using chip::AttributeId;
using chip::ClusterId;
using chip::EndpointId;
using chip::Protocols::InteractionModel::Status;

// emberAfReadAttribute: calls emAfReadOrWriteAttribute (provided by CodegenEmberMocks)
Status emberAfReadAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr, uint16_t readLength)
{
    EmberAfAttributeSearchRecord record;
    const EmberAfAttributeMetadata * metadata = nullptr;
    record.endpoint                           = endpoint;
    record.clusterId                          = cluster;
    record.attributeId                        = attributeID;
    return emAfReadOrWriteAttribute(&record, &metadata, dataPtr, readLength, false);
}

// Stub: attribute change listener — returns nullptr (no real listener needed for tests)
chip::app::DataModel::ProviderChangeListener * emberAfGlobalInteractionModelAttributesChangedListener()
{
    return nullptr;
}

// 5-argument legacy overload of emberAfWriteAttribute (no-op for mock tests)
Status emberAfWriteAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr,
                             EmberAfAttributeType dataType)
{
    using namespace chip::app;
    ConcreteAttributePath path(endpoint, cluster, attributeID);
    EmberAfWriteDataInput input(dataPtr, dataType);
    return emberAfWriteAttribute(path, input);
}

// Stubs for protocol name lookups (referenced by SessionManager via transitive deps)
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
