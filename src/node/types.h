// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! @file
//! Home for public enum and struct type definitions that are used internally
//! by node code, but also used externally by wallet or GUI code.
//!
//! This file is intended to define only simple types that do not have external
//! dependencies. More complicated types should be defined in dedicated header
//! files.

#ifndef BITCOIN_NODE_TYPES_H
#define BITCOIN_NODE_TYPES_H

#include <cstdint>

namespace node {
/**
 * Methods to broadcast a local transaction.
 * Used to influence `BroadcastTransaction()` and its callers.
 */
enum TxBroadcastMethod : uint8_t {
    /// Add the transaction to the mempool and broadcast to all currently connected peers.
    ADD_TO_MEMPOOL_AND_BROADCAST_TO_ALL,
    /// Add the transaction to the mempool, but don't broadcast to anybody.
    ADD_TO_MEMPOOL_NO_BROADCAST,
    /// Omit the mempool and directly send the transaction via a few dedicated connections to
    /// peers on privacy networks.
    NO_MEMPOOL_PRIVATE_BROADCAST,
};
} // namespace node

#endif // BITCOIN_NODE_TYPES_H
