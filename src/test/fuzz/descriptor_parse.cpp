// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <util/memory.h>

void initialize()
{
    static const BasicTestingSetup basic_testing_setup{CBaseChainParams::REGTEST};
}

void test_one_input(const std::vector<uint8_t>& buffer)
{
    const std::string descriptor(buffer.begin(), buffer.end());
    FlatSigningProvider signing_provider;
    std::string error;
    for (const bool require_checksum : {true, false}) {
        const auto desc = Parse(descriptor, signing_provider, error, require_checksum);
        if (desc) {
            (void)desc->ToString();
            (void)desc->IsRange();
            (void)desc->IsSolvable();
        }
    }
}
