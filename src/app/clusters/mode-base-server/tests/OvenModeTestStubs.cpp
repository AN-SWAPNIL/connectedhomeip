/*
 *    Copyright (c) 2025 Project CHIP Authors
 *    Licensed under the Apache License, Version 2.0.
 *
 *    Minimal stubs for mode-base-server test linking.
 *    Provides only the symbols needed by mode-base-server.cpp
 *    that are not available from mock_ember.
 */

#include <app/util/endpoint-config-api.h>
#include <lib/core/DataModelTypes.h>
#include <protocols/Protocols.h>

// emberAfContainsServer is NOT provided by mock_ember's attribute-storage.cpp.
// The real version (src/app/util/attribute-storage.cpp:830) calls emberAfFindServerCluster
// which IS provided by mock_ember. We provide the thin wrapper here.
bool emberAfContainsServer(chip::EndpointId endpoint, chip::ClusterId clusterId)
{
    return (emberAfFindServerCluster(endpoint, clusterId) != nullptr);
}

// GetProtocolName / GetMessageTypeName are diagnostic helpers defined in
// src/protocols/Protocols.cpp. They are referenced from SessionManager.cpp
// (a transitive dep of src/app) but NOT linked by default in test builds.
// Provide trivial stubs since we never exercise transport paths.
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
