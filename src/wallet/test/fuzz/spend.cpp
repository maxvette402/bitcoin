// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/wallet.h>
#include <test/util/setup_common.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

namespace wallet {
namespace {
const TestingSetup* g_setup;

void initialize_setup()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(wallet_create_transaction, .init = initialize_setup)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    const auto& node = g_setup->m_node;
    ArgsManager& args = *node.args;
    args.ForceSetArg("-dustrelayfee", ToString(fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY)));
    FuzzedWallet fuzzed_wallet{
        g_setup->m_node.chain.get(),
        "fuzzed_wallet_a",
        "tprv8ZgxMBicQKsPd1QwsGgzfu2pcPYbBosZhJknqreRHgsWx32nNEhMjGQX2cgFL8n6wz9xdDYwLcs78N4nsCo32cxEX8RBtwGsEGgybLiQJfk",
    };

    CCoinControl coin_control;
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_version = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    coin_control.m_avoid_partial_spends = fuzzed_data_provider.ConsumeBool();
    coin_control.m_include_unsafe_inputs = fuzzed_data_provider.ConsumeBool();
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_confirm_target = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    coin_control.destChange = fuzzed_data_provider.ConsumeBool() ? fuzzed_wallet.GetDestination(fuzzed_data_provider) : ConsumeTxDestination(fuzzed_data_provider);
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_change_type = fuzzed_data_provider.PickValueInArray(OUTPUT_TYPES);
    if (fuzzed_data_provider.ConsumeBool()) coin_control.m_feerate = CFeeRate(ConsumeMoney(fuzzed_data_provider, /*max=*/COIN));
    coin_control.m_allow_other_inputs = fuzzed_data_provider.ConsumeBool();
    coin_control.m_locktime = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    coin_control.fOverrideFeeRate = fuzzed_data_provider.ConsumeBool();

    std::vector<CRecipient> recipients;
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 100) {
        CTxDestination destination;
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                destination = fuzzed_wallet.GetDestination(fuzzed_data_provider);
            },
            [&] {
                CScript script;
                script << OP_RETURN;
                destination = CNoDestination{script};
            },
            [&] {
                destination = ConsumeTxDestination(fuzzed_data_provider);
            }
        );
        recipients.push_back({destination,
                              /*nAmount=*/ConsumeMoney(fuzzed_data_provider),
                              /*fSubtractFeeFromAmount=*/fuzzed_data_provider.ConsumeBool()});
    }

    std::optional<unsigned int> change_pos;
    if (fuzzed_data_provider.ConsumeBool()) change_pos = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    (void)CreateTransaction(*fuzzed_wallet.wallet, recipients, change_pos, coin_control);
}
} // namespace
} // namespace wallet
