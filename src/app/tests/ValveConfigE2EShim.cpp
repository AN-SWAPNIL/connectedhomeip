/**
 * Minimal shim providing missing symbols for Valve Configuration E2E tests.
 * Provides in-memory attribute storage, a no-op System::Layer for
 * DeviceLayer::SystemLayer() calls, and other stubs.
 */

#include <app/SafeAttributePersistenceProvider.h>
#include <app/util/MarkAttributeDirty.h>
#include <app/util/attribute-storage-detail.h>
#include <app/util/attribute-storage.h>
#include <app/util/attribute-table.h>
#include <lib/core/CHIPError.h>
#include <protocols/Protocols.h>
#include <system/SystemLayer.h>

#include <cstring>
#include <map>
#include <tuple>
#include <vector>

using chip::AttributeId;
using chip::ClusterId;
using chip::EndpointId;
using chip::Protocols::InteractionModel::Status;

// ────────────────────────────────────────────────────────────────────────
// Stub: emberAfGetClusterServerEndpointIndex
// Maps endpoint 0 → index 0.  The Valve server calls this to index its
// delegate and remaining-duration tables.
// ────────────────────────────────────────────────────────────────────────
uint16_t emberAfGetClusterServerEndpointIndex(EndpointId endpoint, ClusterId cluster, uint16_t fixedClusterServerEndpointCount)
{
    // For test: endpoint 0 → index 0
    if (endpoint == 0)
    {
        return 0;
    }
    return kEmberInvalidEndpointIndex;
}

// ────────────────────────────────────────────────────────────────────────
// In-memory attribute storage: key = (endpoint, cluster, attribute) → value bytes
// ────────────────────────────────────────────────────────────────────────
static std::map<std::tuple<EndpointId, ClusterId, AttributeId>, std::vector<uint8_t>> sAttributeStore;

void ResetTestAttributeStore()
{
    sAttributeStore.clear();
}

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

chip::app::DataModel::ProviderChangeListener * emberAfGlobalInteractionModelAttributesChangedListener()
{
    return nullptr;
}

Status emberAfWriteAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attributeID, uint8_t * dataPtr,
                             EmberAfAttributeType dataType)
{
    auto key     = std::make_tuple(endpoint, cluster, attributeID);
    uint16_t len = 1;
    switch (dataType)
    {
    case ZCL_INT16U_ATTRIBUTE_TYPE:
    case ZCL_INT16S_ATTRIBUTE_TYPE:
    case ZCL_BITMAP16_ATTRIBUTE_TYPE:
        len = 2;
        break;
    case ZCL_INT32U_ATTRIBUTE_TYPE:
    case ZCL_INT32S_ATTRIBUTE_TYPE:
    case ZCL_EPOCH_S_ATTRIBUTE_TYPE:
    case ZCL_ELAPSED_S_ATTRIBUTE_TYPE:
    case ZCL_BITMAP32_ATTRIBUTE_TYPE:
        len = 4;
        break;
    case ZCL_INT64U_ATTRIBUTE_TYPE:
    case ZCL_INT64S_ATTRIBUTE_TYPE:
    case ZCL_EPOCH_US_ATTRIBUTE_TYPE:
        len = 8;
        break;
    default:
        len = 1;
        break;
    }
    sAttributeStore[key].assign(dataPtr, dataPtr + len);
    return Status::Success;
}

// ────────────────────────────────────────────────────────────────────────
// Protocol name stubs
// ────────────────────────────────────────────────────────────────────────
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

// ────────────────────────────────────────────────────────────────────────
// Stub SafeAttributePersistenceProvider
// ────────────────────────────────────────────────────────────────────────
namespace {

class StubSafeAttributePersistenceProvider : public chip::app::SafeAttributePersistenceProvider
{
public:
    CHIP_ERROR SafeWriteValue(const chip::app::ConcreteAttributePath & aPath, const chip::ByteSpan & aValue) override
    {
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR SafeReadValue(const chip::app::ConcreteAttributePath & aPath, chip::MutableByteSpan & aValue) override
    {
        return CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND;
    }
};

StubSafeAttributePersistenceProvider gStubSafePersistence;

} // namespace

namespace chip {
namespace app {

SafeAttributePersistenceProvider * GetSafeAttributePersistenceProvider()
{
    return &gStubSafePersistence;
}

} // namespace app
} // namespace chip

// ────────────────────────────────────────────────────────────────────────
// No-op System::Layer for DeviceLayer::SystemLayer()
// The Valve server calls CancelTimer/StartTimer — we provide stubs.
// ────────────────────────────────────────────────────────────────────────
namespace {

class NoOpSystemLayer : public chip::System::Layer
{
public:
    CHIP_ERROR Init() override { return CHIP_NO_ERROR; }
    void Shutdown() override {}
    bool IsInitialized() const override { return true; }

    CHIP_ERROR StartTimer(chip::System::Clock::Timeout aDelay, chip::System::TimerCompleteCallback aComplete,
                          void * aAppState) override
    {
        return CHIP_NO_ERROR; // no-op
    }

    CHIP_ERROR ExtendTimerTo(chip::System::Clock::Timeout aDelay, chip::System::TimerCompleteCallback aComplete,
                             void * aAppState) override
    {
        return CHIP_NO_ERROR;
    }

    bool IsTimerActive(chip::System::TimerCompleteCallback onComplete, void * appState) override { return false; }

    chip::System::Clock::Timeout GetRemainingTime(chip::System::TimerCompleteCallback onComplete, void * appState) override
    {
        return chip::System::Clock::Timeout(0);
    }

    void CancelTimer(chip::System::TimerCompleteCallback aOnComplete, void * aAppState) override
    {
        // no-op
    }

    CHIP_ERROR ScheduleWork(chip::System::TimerCompleteCallback aComplete, void * aAppState) override
    {
        return CHIP_NO_ERROR;
    }
};

NoOpSystemLayer gNoOpSystemLayer;

} // namespace

// ────────────────────────────────────────────────────────────────────────
// Provide DeviceLayer::SystemLayer() and SetSystemLayerForTesting()
// so that Valve server .cpp can call DeviceLayer::SystemLayer().CancelTimer()
// without linking against the full platform.
// ────────────────────────────────────────────────────────────────────────
namespace chip {
namespace DeviceLayer {

static chip::System::Layer * gSystemLayerForTesting = nullptr;

void SetSystemLayerForTesting(chip::System::Layer * layer)
{
    gSystemLayerForTesting = layer;
}

chip::System::Layer & SystemLayer()
{
    if (gSystemLayerForTesting != nullptr)
    {
        return *gSystemLayerForTesting;
    }
    return gNoOpSystemLayer;
}

} // namespace DeviceLayer
} // namespace chip
