// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_MINING_H
#define BITCOIN_INTERFACES_MINING_H

namespace node {
struct CBlockTemplate;
struct NodeContext;
} // namespace node

class CBlockIndex;
class BlockValidationState;
class CBlockIndex;

namespace interfaces {

//! Interface giving clients (RPC, Stratum v2 Template Provider in the future)
//! ability to create block templates.

class Mining
{
public:
    virtual ~Mining() {}

    /** If this chain is exclusively used for testing */
    virtual bool isTestChain() = 0;

    //! Returns whether IBD is still in progress. */
    virtual bool isInitialBlockDownload() = 0;

    //! Returns the hash for the tip of this chain, 0 if none
    virtual uint256 getTipHash() = 0;

    /**
     * Processes new block. A valid new block is automatically relayed to peers.
     *
     * @param[in]   block The block we want to process.
     * @param[out]  new_block A boolean which is set to indicate if the block was first received via this call
     * @returns     If the block was processed, independently of block validity
     */
    virtual bool processNewBlock(const std::shared_ptr<const CBlock>& block, bool* new_block) = 0;

    //! Return the number of transaction updates in the mempool,
    //! used to decide whether to make a new block template.
    virtual unsigned int getTransactionsUpdated() = 0;

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    virtual std::unique_ptr<node::CBlockTemplate> createNewBlock(const CScript& scriptPubKeyIn, bool use_mempool = true) = 0;

    /**
     * Check a block is completely valid from start to finish.
     * Only works on top of our current best block.
     * Does not check proof-of-work.
     * */
    virtual bool testBlockValidity(BlockValidationState& state, const CBlock& block, bool check_merkle_root) = 0;

    //! Get internal node context. Useful for RPC and testing,
    //! but not accessible across processes.
    virtual node::NodeContext* context() { return nullptr; }
};

//! Return implementation of Mining interface.
std::unique_ptr<Mining> MakeMining(node::NodeContext& node);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_MINING_H
