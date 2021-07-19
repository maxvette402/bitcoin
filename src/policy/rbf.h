// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_RBF_H
#define BITCOIN_POLICY_RBF_H

#include <txmempool.h>

/** Maximum number of transactions that can be replaced by BIP125 RBF (Rule #5). This includes all
 * mempool conflicts and their descendants. */
static constexpr uint32_t MAX_BIP125_REPLACEMENT_CANDIDATES{100};

/** Get all descendants of setIterConflicting. Also enforce BIP125 Rule #5, "The number of original
 * transactions to be replaced and their descendant transactions which will be evicted from the
 * mempool must not exceed a total of 100 transactions." Quit as early as possible. There cannot be
 * more than MAX_BIP125_REPLACEMENT_CANDIDATES potential entries.
 * @param[in]   setIterConflicting  The set of iterators to mempool entries.
 * @param[out]  err_string          Used to return errors, if any.
 * @param[out]  allConflicting      Populated with all the mempool entries that would be replaced,
 *                                  which includes descendants of setIterConflicting. Not cleared at
 *                                  the start; any existing mempool entries will remain in the set.
 * @returns false if Rule 5 is broken.
 */
bool GetEntriesForConflicts(const CTransaction& tx, CTxMemPool& m_pool,
                            const CTxMemPool::setEntries& setIterConflicting,
                            CTxMemPool::setEntries& allConflicting,
                            std::string& err_string) EXCLUSIVE_LOCKS_REQUIRED(m_pool.cs);
#endif // BITCOIN_POLICY_RBF_H
