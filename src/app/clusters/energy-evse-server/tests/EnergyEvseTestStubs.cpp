/*
 *    Copyright (c) 2025 Project CHIP Authors
 *    Licensed under the Apache License, Version 2.0.
 *
 *    Minimal stubs for energy-evse-server test linking.
 *    Provides symbols needed by the production .cpp file
 *    that are not available from mock_ember.
 */

#include <app/util/endpoint-config-api.h>
#include <lib/core/DataModelTypes.h>
#include <protocols/Protocols.h>

// emberAfContainsServer is NOT provided by mock_ember's attribute-storage.cpp.
// The real version calls emberAfFindServerCluster which IS provided by mock_ember.
bool emberAfContainsServer(chip::EndpointId endpoint, chip::ClusterId clusterId)
{
    return (emberAfFindServerCluster(endpoint, clusterId) != nullptr);
}

// GetProtocolName / GetMessageTypeName are diagnostic helpers referenced
// transitively from src/app but not linked in test builds.
namespace chip {
namespace Protocols {

const char * GetProtocolName(Id protocolId)
{
    return "test";
}

const char * GetMessageTypeName(Id protocolId, uint8_t msgType)
{
    return "test";
}

} // namespace Protocols
} // namespace chip
