// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <node/context.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/fees.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <random>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(coinselection_tests, WalletTestingSetup)

static int nextLockTime = 0;
static FastRandomContext default_rand;

/** Default coin selection parameters (dcsp) allow us to only explicitly set
 * parameters when a diverging value is relevant in the context of a test. */
static CoinSelectionParams init_default_params()
{
    CoinSelectionParams dcsp{
        /*rng_fast*/ default_rand,
        /*change_output_size=*/ 31,
        /*change_spend_size=*/ 68,
        /*min_change_target=*/ 50'000,
        /*effective_feerate=*/ CFeeRate(5000),
        /*long_term_feerate=*/ CFeeRate(10'000),
        /*discard_feerate=*/ CFeeRate(3000),
        /*tx_noinputs_size=*/ 11 + 31, //static header size + output size
        /*avoid_partial=*/ false,
    };
    dcsp.m_change_fee = /*155 sats=*/ dcsp.m_effective_feerate.GetFee(dcsp.change_output_size);
    dcsp.m_cost_of_change = /*204 + 155 sats=*/ dcsp.m_discard_feerate.GetFee(dcsp.change_spend_size) + dcsp.m_change_fee;
    dcsp.min_viable_change = /*204 sats=*/ dcsp.m_discard_feerate.GetFee(dcsp.change_spend_size);
    dcsp.m_subtract_fee_outputs = false;
    return dcsp;
}

static const CoinSelectionParams default_cs_params = init_default_params();

/** Make one coin that either has a given effective value (default) or a given amount (`is_eff_value = false`). */
static COutput MakeCoin(const CAmount& amount, bool is_eff_value = true, int nInput = 0, CFeeRate feerate = default_cs_params.m_effective_feerate, int custom_spending_vsize = 68)
{
    CMutableTransaction tx;
    tx.vout.resize(nInput + 1);
    CAmount fees = feerate.GetFee(custom_spending_vsize);
    tx.vout[nInput].nValue = amount + int(is_eff_value) * fees;
    tx.nLockTime = nextLockTime++;        // so all transactions get different hashes
    return COutput{COutPoint(tx.GetHash(), nInput), tx.vout.at(nInput), /*depth=*/ 1, /*input_bytes=*/ custom_spending_vsize, /*spendable=*/ true, /*solvable=*/ true, /*safe=*/ true, /*time=*/ 0, /*from_me=*/ false, /*fees=*/ fees};
}

/** Make multiple coins with given effective values */
static void AddCoins(std::vector<COutput>& utxo_pool, std::vector<CAmount> coins, CFeeRate feerate = default_cs_params.m_effective_feerate)
{
    for (int c : coins) {
        utxo_pool.push_back(MakeCoin(c, true, 0, feerate));
    }
}

/** Group available coins into OutputGroups */
inline std::vector<OutputGroup>& GroupCoins(const std::vector<COutput>& available_coins, const CoinSelectionParams& cs_params = default_cs_params, bool subtract_fee_outputs = false)
{
    static std::vector<OutputGroup> static_groups;
    static_groups.clear();
    for (auto& coin : available_coins) {
        static_groups.emplace_back(cs_params);
        OutputGroup& group = static_groups.back();
        group.Insert(std::make_shared<COutput>(coin), /*ancestors=*/ 0, /*descendants=*/ 0);
        group.m_subtract_fee_outputs = subtract_fee_outputs;
    }
    return static_groups;
}

/** Check if SelectionResult a is equivalent to SelectionResult b.
 * Equivalent means same input values, but maybe different inputs (i.e. same value, different prevout) */
static bool EquivalentResult(const SelectionResult& a, const SelectionResult& b)
{
    std::vector<CAmount> a_amts;
    std::vector<CAmount> b_amts;
    for (const auto& coin : a.GetInputSet()) {
        a_amts.push_back(coin->txout.nValue);
    }
    for (const auto& coin : b.GetInputSet()) {
        b_amts.push_back(coin->txout.nValue);
    }
    std::sort(a_amts.begin(), a_amts.end());
    std::sort(b_amts.begin(), b_amts.end());

    std::pair<std::vector<CAmount>::iterator, std::vector<CAmount>::iterator> ret = std::mismatch(a_amts.begin(), a_amts.end(), b_amts.begin());
    return ret.first == a_amts.end() && ret.second == b_amts.end();
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
