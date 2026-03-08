/**
 * In-memory attribute storage shim for Window Covering E2E and spec-gap tests.
 *
 * Provides WindowCoveringTestShim::Reset() and overrides emberAfReadAttribute /
 * emberAfWriteAttribute so that the generated Accessors (Get/Set) work without
 * a real data-model backend.
 */
#pragma once

struct WindowCoveringTestShim
{
    static void Reset();
};
