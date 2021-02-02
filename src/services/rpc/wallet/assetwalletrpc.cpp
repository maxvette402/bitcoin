﻿// Copyright (c) 2013-2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <validation.h>
#include <services/rpc/wallet/assetwalletrpc.h>
#include <boost/algorithm/string.hpp>
#include <rpc/util.h>
#include <rpc/blockchain.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/fees.h>
#include <policy/policy.h>
#include <consensus/validation.h>
#include <wallet/coincontrol.h>
#include <rpc/server.h>
#include <chainparams.h>
#include <util/moneystr.h>
#include <util/fees.h>
#include <util/translation.h>
#include <core_io.h>
#include <services/asset.h>
#include <node/transaction.h>
#include <rpc/auxpow_miner.h>
#include <services/rpc/assetrpc.h>
#include <messagesigner.h>
#include <rpc/rawtransaction_util.h>
extern std::string EncodeDestination(const CTxDestination& dest);
extern CTxDestination DecodeDestination(const std::string& str);
UniValue SendMoney(CWallet* const pwallet, const CCoinControl &coin_control, std::vector<CRecipient> &recipients, mapValue_t map_value, bool verbose);
uint64_t nCustomAssetGuid = 0;
void CreateFeeRecipient(CScript& scriptPubKey, CRecipient& recipient) {
    CRecipient recp = { scriptPubKey, 0, false };
    recipient = recp;
}

bool ListTransactionSyscoinInfo(const CWalletTx& wtx, const CAssetCoinInfo assetInfo, const std::string strCategory, UniValue& output) {
    bool found = false;
    if(IsSyscoinMintTx(wtx.tx->nVersion)) {
        found = AssetMintWtxToJson(wtx, assetInfo, strCategory, output);
    }
    else if (IsAssetTx(wtx.tx->nVersion) || IsAssetAllocationTx(wtx.tx->nVersion)) {
        found = SysWtxToJSON(wtx, assetInfo, strCategory, output);
    }
    return found;
}

bool SysWtxToJSON(const CWalletTx& wtx, const CAssetCoinInfo &assetInfo, const std::string &strCategory, UniValue& output) {
    bool found = false;
    if (IsAssetTx(wtx.tx->nVersion) && wtx.tx->nVersion != SYSCOIN_TX_VERSION_ASSET_SEND)
        found = AssetWtxToJSON(wtx, assetInfo, strCategory, output);
    else if (IsAssetAllocationTx(wtx.tx->nVersion) || wtx.tx->nVersion == SYSCOIN_TX_VERSION_ASSET_SEND)
        found = AssetAllocationWtxToJSON(wtx, assetInfo, strCategory, output);
    return found;
}

bool AssetWtxToJSON(const CWalletTx &wtx, const CAssetCoinInfo &assetInfo, const std::string &strCategory, UniValue &entry) {
    if(!AllocationWtxToJson(wtx, assetInfo, strCategory, entry))
        return false;
    const uint32_t &nBaseAsset = GetBaseAssetID(assetInfo.nAsset);
    CAsset asset(*wtx.tx);
    if (!asset.IsNull()) {
        if(asset.nUpdateMask & ASSET_INIT)  {
            entry.__pushKV("symbol", DecodeBase64(asset.strSymbol));
            entry.__pushKV("max_supply", ValueFromAmount(asset.nMaxSupply, nBaseAsset));
            entry.__pushKV("precision", asset.nPrecision);
        }

        if(asset.nUpdateMask & ASSET_UPDATE_DATA) 
            entry.__pushKV("public_value", AssetPublicDataToJson(asset.strPubData));

        if(asset.nUpdateMask & ASSET_UPDATE_CONTRACT) 
            entry.__pushKV("contract", "0x" + HexStr(asset.vchContract));
        
        if(asset.nUpdateMask & ASSET_UPDATE_NOTARY_KEY) 
            entry.__pushKV("notary_address", EncodeDestination(WitnessV0KeyHash(uint160{asset.vchNotaryKeyID})));

        if(asset.nUpdateMask & ASSET_UPDATE_AUXFEE) {
            UniValue value(UniValue::VOBJ);
            asset.auxFeeDetails.ToJson(value, nBaseAsset);
            entry.__pushKV("auxfee", value);
        }

        if(asset.nUpdateMask & ASSET_UPDATE_NOTARY_DETAILS) {
            UniValue value(UniValue::VOBJ);
            asset.notaryDetails.ToJson(value);
            entry.__pushKV("notary_details", value);
        }

        if(asset.nUpdateMask & ASSET_UPDATE_CAPABILITYFLAGS) 
            entry.__pushKV("updatecapability_flags", asset.nUpdateCapabilityFlags);

        entry.__pushKV("update_flags", asset.nUpdateMask);
    }
    return true;
}

bool AssetAllocationWtxToJSON(const CWalletTx &wtx, const CAssetCoinInfo &assetInfo, const std::string &strCategory, UniValue &entry) {
    if(!AllocationWtxToJson(wtx, assetInfo, strCategory, entry))
        return false;
    if(wtx.tx->nVersion == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_ETHEREUM){
         CBurnSyscoin burnSyscoin (*wtx.tx);
         if (!burnSyscoin.IsNull()) {
            CAsset dbAsset;
            GetAsset(GetBaseAssetID(assetInfo.nAsset), dbAsset);
            entry.__pushKV("ethereum_destination", "0x" + HexStr(burnSyscoin.vchEthAddress));
            entry.__pushKV("ethereum_contract", "0x" + HexStr(dbAsset.vchContract));
            return true;
         }
         return false;
    }
    return true;
}
bool AssetMintWtxToJson(const CWalletTx &wtx, const CAssetCoinInfo &assetInfo, const std::string &strCategory, UniValue &entry) {
    if(!AllocationWtxToJson(wtx, assetInfo, strCategory, entry))
        return false;
    CMintSyscoin mintSyscoin(*wtx.tx);
    if (!mintSyscoin.IsNull()) {
        UniValue oSPVProofObj(UniValue::VOBJ);
        oSPVProofObj.__pushKV("bridgetransferid", mintSyscoin.nBridgeTransferID);  
        oSPVProofObj.__pushKV("postx", mintSyscoin.posTx);
        oSPVProofObj.__pushKV("txroot", HexStr(mintSyscoin.vchTxRoot));
        oSPVProofObj.__pushKV("txparentnodes", HexStr(mintSyscoin.vchTxParentNodes)); 
        oSPVProofObj.__pushKV("txpath", HexStr(mintSyscoin.vchTxPath));
        oSPVProofObj.__pushKV("posReceipt", mintSyscoin.posReceipt); 
        oSPVProofObj.__pushKV("receiptroot", HexStr(mintSyscoin.vchReceiptRoot));  
        oSPVProofObj.__pushKV("receiptparentnodes", HexStr(mintSyscoin.vchReceiptParentNodes)); 
        oSPVProofObj.__pushKV("ethblocknumber", mintSyscoin.nBlockNumber); 
        entry.__pushKV("spv_proof", oSPVProofObj); 
        UniValue oAssetAllocationReceiversArray(UniValue::VARR);
        for(const auto &it: mintSyscoin.voutAssets) {
            CAmount nTotal = 0;
            UniValue oAssetAllocationReceiversObj(UniValue::VOBJ);
            const uint64_t &nAsset = it.key;
            const uint32_t &nBaseAsset = GetBaseAssetID(nAsset);
            oAssetAllocationReceiversObj.__pushKV("asset_guid", nAsset);
            if(!it.vchNotarySig.empty()) {
                oAssetAllocationReceiversObj.__pushKV("notary_sig", HexStr(it.vchNotarySig));
            }
            UniValue oAssetAllocationReceiverOutputsArray(UniValue::VARR);
            for(const auto& voutAsset: it.values){
                nTotal += voutAsset.nValue;
                UniValue oAssetAllocationReceiverOutputObj(UniValue::VOBJ);
                oAssetAllocationReceiverOutputObj.__pushKV("n", voutAsset.n);
                oAssetAllocationReceiverOutputObj.__pushKV("amount", ValueFromAmount(voutAsset.nValue, nBaseAsset));
                oAssetAllocationReceiverOutputsArray.push_back(oAssetAllocationReceiverOutputObj);
            }
            oAssetAllocationReceiversObj.__pushKV("outputs", oAssetAllocationReceiverOutputsArray); 
            oAssetAllocationReceiversObj.__pushKV("total", ValueFromAmount(nTotal, nBaseAsset));
            oAssetAllocationReceiversArray.push_back(oAssetAllocationReceiversObj);
        }
        entry.__pushKV("allocations", oAssetAllocationReceiversArray);
    }
    return true;
}

bool AllocationWtxToJson(const CWalletTx &wtx, const CAssetCoinInfo &assetInfo, const std::string &strCategory, UniValue &entry) {
    entry.__pushKV("txtype", stringFromSyscoinTx(wtx.tx->nVersion));
    entry.__pushKV("asset_guid", assetInfo.nAsset);
    if(IsAssetAllocationTx(wtx.tx->nVersion)) {
        entry.__pushKV("amount", ValueFromAmount(assetInfo.nValue, GetBaseAssetID(assetInfo.nAsset)));
        entry.__pushKV("action", strCategory);
    }
    return true;
}

static RPCHelpMan signhash()
{   
    return RPCHelpMan{"signhash",
            "\nSign a hash with the private key of an address" +
    HELP_REQUIRING_PASSPHRASE,
            {
                {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The syscoin address to use for the private key."},
                {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash to create a signature of."},
            },
            RPCResult{
                RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
            },
            RPCExamples{
        "\nUnlock the wallet for 30 seconds\n"
        + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
        "\nCreate the signature\n"
        + HelpExampleCli("signhash", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"hash\"") +
        "\nAs a JSON-RPC call\n"
        + HelpExampleRpc("signhash", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"hash\"")
            },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
        RPCHelpMan{"signhash",
                "\nSign a hash with the private key of an address" +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The syscoin address to use for the private key."},
                    {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash to create a signature of."},
                },
                RPCResult{
                    RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
                },
                RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signhash", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"hash\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signhash", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"hash\"")
                },
            }.Check(request);

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*wallet);

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    uint256 hash = ParseHashV(request.params[1], "hash");

    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    auto keyid = GetKeyForDestination(spk_man, dest);
    if (keyid.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CKey vchSecret;
    if (!spk_man.GetKey(keyid, vchSecret)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    std::vector<unsigned char> vchSig;
    if(!CHashSigner::SignHash(hash, vchSecret, vchSig)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "SignHash failed");
    }
   
    if (!CHashSigner::VerifyHash(hash, vchSecret.GetPubKey(), vchSig)) {
        LogPrintf("Sign -- VerifyHash() failed\n");
        return false;
    }
    return EncodeBase64(vchSig);
},
    };
} 

static RPCHelpMan signmessagebech32()
{
    return RPCHelpMan{"signmessagebech32",
                "\nSign a message with the private key of an address (p2pkh or p2wpkh)" +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The syscoin address to use for the private key."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Message to sign."},
                },
                RPCResult{
                    RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
                },
                RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagebech32", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"message\"") +
            "\nAs a JSON-RPC signmessagebech32\n"
            + HelpExampleRpc("signmessagebech32", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"message\"")
                },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    const CWallet* const pwallet = wallet.get();

    LegacyScriptPubKeyMan& spk_man = EnsureLegacyScriptPubKeyMan(*wallet);

    LOCK2(pwallet->cs_wallet, spk_man.cs_KeyStore);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    auto keyid = GetKeyForDestination(spk_man, dest);
    if (keyid.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CKey vchSecret;
    if (!spk_man.GetKey(keyid, vchSecret)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    std::vector<unsigned char> vchSig;
    if(!CMessageSigner::SignMessage(strMessage, vchSig, vchSecret)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "SignMessage failed");
    }
   
    if (!CMessageSigner::VerifyMessage(vchSecret.GetPubKey(), vchSig, strMessage)) {
        LogPrintf("Sign -- VerifyMessage() failed\n");
        return false;
    }
    return EncodeBase64(vchSig);
},
    };
} 

static RPCHelpMan syscoinburntoassetallocation()
{
    return RPCHelpMan{"syscoinburntoassetallocation",
        "\nBurns Syscoin to the SYSX asset\n",
        {
            {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset guid of SYSX"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of SYS to burn."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }},
        RPCExamples{
            HelpExampleCli("syscoinburntoassetallocation", "\"asset_guid\" \"amount\"")
            + HelpExampleRpc("syscoinburntoassetallocation", "\"asset_guid\", \"amount\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue &params = request.params;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);
    const uint64_t &nAsset = params[0].get_uint64();          	
	CAssetAllocation theAssetAllocation;
	CAsset theAsset;
	if (!GetAsset(GetBaseAssetID(nAsset), theAsset))
		throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");

    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    CTxDestination dest;
    std::string errorStr;
    if (!pwallet->GetNewChangeDestination(pwallet->m_default_address_type, dest, errorStr)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, errorStr);
    }

    const CScript& scriptPubKey = GetScriptForDestination(dest);
    CTxOut change_prototype_txout(0, scriptPubKey);
    CRecipient recp = {scriptPubKey, GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet)), false };


    CMutableTransaction mtx;
    CAmount nAmount;
    try{
        nAmount = AssetAmountFromValue(params[1], theAsset.nPrecision);
    }
    catch(...) {
        nAmount = params[1].get_int64();
    }

    std::vector<CAssetOutValue> outVec = {CAssetOutValue(1, nAmount)};
    theAssetAllocation.voutAssets.emplace_back(CAssetOut(nAsset, outVec));

    std::vector<unsigned char> data;
    theAssetAllocation.SerializeData(data); 
    
    CScript scriptData;
    scriptData << OP_RETURN << data;  
    CRecipient burn;
    CreateFeeRecipient(scriptData, burn);
    burn.nAmount = nAmount;
    std::vector<CRecipient> vecSend;
    vecSend.push_back(burn);
    vecSend.push_back(recp);
    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
    int nChangePosRet = -1;
    bilingual_str error;
    CAmount nFeeRequired = 0;
    CTransactionRef tx;
    FeeCalculation fee_calc_out;
    if (!pwallet->CreateTransaction(vecSend, tx, nFeeRequired, nChangePosRet, error, coin_control, fee_calc_out, true /* sign*/, SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, error.original);
    }
    std::string err_string;
    AssertLockNotHeld(cs_main);
    NodeContext& node = EnsureNodeContext(request.context);
    const TransactionError err = BroadcastTransaction(node, tx, err_string, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), /*relay*/ true, /*wait_callback*/ false);
    if (TransactionError::OK != err) {
        throw JSONRPCTransactionError(err, err_string);
    }
    UniValue res(UniValue::VOBJ);
    res.__pushKV("txid", tx->GetHash().GetHex());
    return res;
},
    };
} 


RPCHelpMan assetnew()
{
    return RPCHelpMan{"assetnew",
    "\nCreate a new asset\n",
    {
        {"funding_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Fund resulting UTXO owning the asset by this much SYS for gas."},
        {"symbol", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset symbol (1-8 characters)"},
        {"description", RPCArg::Type::STR, RPCArg::Optional::NO, "Public description of the token."},
        {"contract", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Ethereum token contract for SyscoinX bridge. Must be in hex and not include the '0x' format tag. For example contract '0xb060ddb93707d2bc2f8bcc39451a5a28852f8d1d' should be set as 'b060ddb93707d2bc2f8bcc39451a5a28852f8d1d'. Leave empty for no smart contract bridge."},
        {"precision", RPCArg::Type::NUM, RPCArg::Optional::NO, "Precision of balances. Must be between 0 and 8. The lower it is the higher possible max_supply is available since the supply is represented as a 64 bit integer. With a precision of 8 the max supply is 10 billion."},
        {"max_supply", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Maximum supply of this asset. Depends on the precision value that is set, the lower the precision the higher max_supply can be."},
        {"updatecapability_flags", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Ability to update certain fields. Must be decimal value which is a bitmask for certain rights to update. The bitmask 1 represents the ability to update public data field, 2 for updating the smart contract field, 4 for updating supply, 8 for updating notary address, 16 for updating notary details, 32 for updating auxfee details, 64 for ability to update the capability flags (this field). 127 for all. 0 for none (not updatable)."},
        {"notary_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Notary address"},
        {"notary_details", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Notary details structure (if notary_address is set)",
            {
                {"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "Notary API endpoint (if applicable)"},
                {"instant_transfers", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Enforced double-spend prevention on Notary for Instant Transfers"},
                {"hd_required", RPCArg::Type::BOOL, RPCArg::Optional::NO, "If Notary requires HD Wallet approval (for sender approval specifically applicable to change address schemes), usually in the form of account XPUB or Verifiable Credential of account XPUB using DID"},  
            }
        },
        {"auxfee_details", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Auxiliary fee structure (may be enforced if notary is set)",
            {
                {"auxfee_address", RPCArg::Type::STR, RPCArg::Optional::NO, "AuxFee address"},
                {"fee_struct", RPCArg::Type::ARR, RPCArg::Optional::NO, "Auxiliary fee structure",
                    {
                        {"", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Bound (in amount) for for the fee level based on total transaction amount"},
                        {"", RPCArg::Type::NUM, RPCArg::Optional::NO, "The percentage in %% to share with the operator. The value must be\n"
                                        "between 0.00(0%%) and 0.65535(65.535%%)."},
                    },
                }
            }
        }

    },
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            {RPCResult::Type::NUM, "asset_guid", "The unique identifier of the new asset"}
        }},
    RPCExamples{
    HelpExampleCli("assetnew", "1 \"CAT\" \"publicvalue\" \"contractaddr\" 8 1000 127 \"notary_address\" {} {}")
    + HelpExampleRpc("assetnew", "1, \"CAT\", \"publicvalue\", \"contractaddr\", 8, 1000, 127, \"notary_address\", {}, {}")
    },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint64_t nCustomGuid = nCustomAssetGuid;
    if(nCustomAssetGuid > 0)
        nCustomAssetGuid = 0;
    const UniValue &params = request.params;
    
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();  
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);
    CAmount nGas;
    std::string strSymbol = params[1].get_str();
    std::string strPubData = params[2].get_str();
    if(strPubData == "''")
        strPubData.clear();
    std::string strContract = params[3].get_str();
    if(strContract == "''")
        strContract.clear();
    if(!strContract.empty())
         boost::erase_all(strContract, "0x");  // strip 0x in hex str if exist

    uint32_t precision = params[4].get_uint();
    UniValue param0 = params[0];
    try{
        nGas = AmountFromValue(param0);
    }
    catch(...) {
        nGas = 0;
    }
    CAmount nMaxSupply;
    try{
        nMaxSupply = AssetAmountFromValue(params[5], precision);
    }
    catch(...) {
        nMaxSupply = params[5].get_int64();
    }
    uint32_t nUpdateCapabilityFlags = ASSET_CAPABILITY_ALL;
    if(!params[6].isNull()) {
        nUpdateCapabilityFlags = params[6].get_uint();
    }
    
    std::vector<unsigned char> vchNotaryKeyID;
    if(!params[7].isNull()) {
        std::string strNotary = params[7].get_str();
        if(!strNotary.empty()) {
            CTxDestination txDest = DecodeDestination(strNotary);
            if (!IsValidDestination(txDest)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Invalid notary address");
            }
            if (auto witness_id = std::get_if<WitnessV0KeyHash>(&txDest)) {	
                CKeyID keyID = ToKeyID(*witness_id);
                vchNotaryKeyID = std::vector<unsigned char>(keyID.begin(), keyID.end());
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Invalid notary address: Please use P2PWKH address.");
            }
        }
    }
    CNotaryDetails notaryDetails(params[8]);
    CAuxFeeDetails auxFeeDetails(params[9], precision);
    // calculate net
    // build asset object
    CAsset newAsset;

    UniValue publicData(UniValue::VOBJ);
    publicData.pushKV("desc", EncodeBase64(strPubData));
    uint8_t nUpdateMask = ASSET_INIT;
    const std::string &strPubDataField  = publicData.write();
    std::vector<CAssetOutValue> outVec = {CAssetOutValue(0, 0)};
    newAsset.voutAssets.emplace_back(CAssetOut(0, outVec));
    newAsset.strSymbol = EncodeBase64(strSymbol);
    if(!strPubDataField.empty()) {
        nUpdateMask |= ASSET_UPDATE_DATA;
        newAsset.strPubData = strPubDataField;
    }
    if(!strContract.empty()) {
        nUpdateMask |= ASSET_UPDATE_CONTRACT;
        newAsset.vchContract = ParseHex(strContract);
    }
    if(!vchNotaryKeyID.empty()) {
        nUpdateMask |= ASSET_UPDATE_NOTARY_KEY;
        newAsset.vchNotaryKeyID = vchNotaryKeyID;
    }
    if(!notaryDetails.IsNull()) {
        nUpdateMask |= ASSET_UPDATE_NOTARY_DETAILS;
        newAsset.notaryDetails = notaryDetails;
    }
    if(!auxFeeDetails.IsNull()) {
        nUpdateMask |= ASSET_UPDATE_AUXFEE;
        newAsset.auxFeeDetails = auxFeeDetails;
    }
    if(nUpdateCapabilityFlags != 0) {
        nUpdateMask |= ASSET_UPDATE_CAPABILITYFLAGS;
        newAsset.nPrevUpdateCapabilityFlags = nUpdateCapabilityFlags;
    }
    newAsset.nUpdateMask = nUpdateMask;
    newAsset.nMaxSupply = nMaxSupply;
    newAsset.nPrecision = precision;
    newAsset.nUpdateCapabilityFlags = nUpdateCapabilityFlags;
    
    std::vector<unsigned char> data;
    newAsset.SerializeData(data);
    // use the script pub key to create the vecsend which sendmoney takes and puts it into vout
    std::vector<CRecipient> vecSend;

    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }
    CTxDestination dest;
    std::string errorStr;
    if (!pwallet->GetNewChangeDestination(pwallet->m_default_address_type, dest, errorStr)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, errorStr);
    }
    CMutableTransaction mtx;
    std::set<int> setSubtractFeeFromOutputs;
    // new/send/update all have asset utxo's with 0 asset amount
    const CScript& scriptPubKey = GetScriptForDestination(dest);
    CTxOut change_prototype_txout(nGas, scriptPubKey);
    bool isDust = nGas < COIN;
    CRecipient recp = { scriptPubKey, isDust? GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet)): nGas,  !isDust};
    mtx.vout.push_back(CTxOut(recp.nAmount, recp.scriptPubKey));
    if(nGas > 0)
        setSubtractFeeFromOutputs.insert(0);
    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient opreturnRecipient;
    CreateFeeRecipient(scriptData, opreturnRecipient);
    // 150 SYS fee for new asset
    opreturnRecipient.nAmount = COST_ASSET;
    
    mtx.vout.push_back(CTxOut(opreturnRecipient.nAmount, opreturnRecipient.scriptPubKey));
    CAmount nFeeRequired = 0;
    bilingual_str error;
    int nChangePosRet = -1;
    CCoinControl coin_control;
    // assetnew must not be replaceable
    coin_control.m_signal_bip125_rbf = false;
    coin_control.m_min_depth = 1;
    bool lockUnspents = false;   
    mtx.nVersion = SYSCOIN_TX_VERSION_ASSET_ACTIVATE;
    if (!pwallet->FundTransaction(mtx, nFeeRequired, nChangePosRet, error, lockUnspents, setSubtractFeeFromOutputs, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }
    data.clear();
    // generate deterministic guid based on input txid
    const uint64_t &nAsset = nCustomGuid != 0? nCustomGuid: (uint64_t)GenerateSyscoinGuid(mtx.vin[0].prevout);
    newAsset.voutAssets.clear();
    newAsset.voutAssets.emplace_back(CAssetOut(nAsset, outVec));
    newAsset.SerializeData(data);
    scriptData.clear();
    scriptData << OP_RETURN << data;
    CreateFeeRecipient(scriptData, opreturnRecipient);
    // 150 SYS fee for new asset
    opreturnRecipient.nAmount = COST_ASSET;
    mtx.vout.clear();
    mtx.vout.push_back(CTxOut(recp.nAmount, recp.scriptPubKey));
    mtx.vout.push_back(CTxOut(opreturnRecipient.nAmount, opreturnRecipient.scriptPubKey));
    nFeeRequired = 0;
    nChangePosRet = -1;
    if (!pwallet->FundTransaction(mtx, nFeeRequired, nChangePosRet, error, lockUnspents, setSubtractFeeFromOutputs, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }
    if(pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        UniValue result(UniValue::VOBJ);
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, false /* sign */, true /* bip32derivs */);
        CHECK_NONFATAL(err == TransactionError::OK);
        CHECK_NONFATAL(!complete);
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        return result;
    }
    // Script verification errors
    std::map<int, std::string> input_errors;
    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    pwallet->chain().findCoins(coins);
    bool complete = pwallet->SignTransaction(mtx, coins, SIGHASH_ALL, input_errors);
    if(!complete) {
        UniValue result(UniValue::VOBJ);
        SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
        return result;
    }
    // need to reload asset as notary signature may have gotten added and this is needed in voutAssets so consensus validation passes for notary check
    mtx.LoadAssets();
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    std::string err_string;
    AssertLockNotHeld(cs_main);
    NodeContext& node = EnsureNodeContext(request.context);
    const TransactionError err = BroadcastTransaction(node, tx, err_string, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), /*relay*/ true, /*wait_callback*/ false);
    if (TransactionError::OK != err) {
        throw JSONRPCTransactionError(err, err_string);
    }
    UniValue res(UniValue::VOBJ);
    res.__pushKV("txid", tx->GetHash().GetHex());
    res.__pushKV("asset_guid", nAsset);
    return res;
},
    };
} 

static RPCHelpMan assetnewtest()
{
    return RPCHelpMan{"assetnewtest",
    "\nCreate a new asset for testing purposes with a specific asset_guid. Used by functional tests.\n",
    {
        {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Create asset with this GUID. Only on regtest."},
        {"funding_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Fund resulting UTXO owning the asset by this much SYS for gas."},
        {"symbol", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset symbol (1-8 characters)"},
        {"description", RPCArg::Type::STR, RPCArg::Optional::NO, "Public description of the token."},
        {"contract", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Ethereum token contract for SyscoinX bridge. Must be in hex and not include the '0x' format tag. For example contract '0xb060ddb93707d2bc2f8bcc39451a5a28852f8d1d' should be set as 'b060ddb93707d2bc2f8bcc39451a5a28852f8d1d'. Leave empty for no smart contract bridge."},
        {"precision", RPCArg::Type::NUM, RPCArg::Optional::NO, "Precision of balances. Must be between 0 and 8. The lower it is the higher possible max_supply is available since the supply is represented as a 64 bit integer. With a precision of 8 the max supply is 10 billion."},
        {"max_supply", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Maximum supply of this asset. Depends on the precision value that is set, the lower the precision the higher max_supply can be."},
        {"updatecapability_flags", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Ability to update certain fields. Must be decimal value which is a bitmask for certain rights to update. The bitmask 1 represents the ability to update public data field, 2 for updating the smart contract field, 4 for updating supply, 8 for updating notary address, 16 for updating notary details, 32 for updating auxfee details, 64 for ability to update the capability flags (this field). 127 for all. 0 for none (not updatable)."},
        {"notary_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Notary address"},
        {"notary_details", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Notary details structure (if notary_address is set)",
            {
                {"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "Notary API endpoint (if applicable)"},
                {"instant_transfers", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Enforced double-spend prevention on Notary for Instant Transfers"},
                {"hd_required", RPCArg::Type::BOOL, RPCArg::Optional::NO, "If Notary requires HD Wallet approval (for sender approval specifically applicable to change address schemes), usually in the form of account XPUB or Verifiable Credential of account XPUB using DID"},  
            }
        },
        {"auxfee_details", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Auxiliary fee structure (may be enforced if notary is set)",
            {
                {"auxfee_address", RPCArg::Type::STR, RPCArg::Optional::NO, "AuxFee address"},
                {"fee_struct", RPCArg::Type::ARR, RPCArg::Optional::NO, "Auxiliary fee structure",
                    {
                        {"", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Bound (in amount) for for the fee level based on total transaction amount"},
                        {"", RPCArg::Type::NUM, RPCArg::Optional::NO, "The percentage in %% to share with the operator. The value must be\n"
                                        "between 0.00(0%%) and 0.65535(65.535%%)."},
                    },
                }
            }
        }

    },
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            {RPCResult::Type::NUM, "asset_guid", "The unique identifier of the new asset"}
        }},
    RPCExamples{
    HelpExampleCli("assetnew", "1 \"CAT\" \"publicvalue\" \"contractaddr\" 8 1000 127 \"notary_address\" {} {}")
    + HelpExampleRpc("assetnew", "1, \"CAT\", \"publicvalue\", \"contractaddr\", 8, 1000, 127, \"notary_address\", {}, {}")
    },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue &params = request.params;
    UniValue paramsFund(UniValue::VARR);
    nCustomAssetGuid = params[0].get_uint64();
    for(int i = 1;i<=10;i++)
        paramsFund.push_back(params[i]);
    JSONRPCRequest assetNewRequest(request.context);
    assetNewRequest.params = paramsFund;
    assetNewRequest.URI = request.URI;
    return assetnew().HandleRequest(assetNewRequest);        
},
    };
}
UniValue CreateAssetUpdateTx(const util::Ref& context, const int32_t& nVersionIn, const uint64_t &nAsset, CWallet* const pwallet, std::vector<CRecipient>& vecSend, const CRecipient& opreturnRecipient,const CRecipient* recpIn = nullptr) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
    AssertLockHeld(pwallet->cs_wallet);
    CCoinControl coin_control;
    CAmount nMinimumAmountAsset = 0;
    CAmount nMaximumAmountAsset = 0;
    CAmount nMinimumSumAmountAsset = 0;
    coin_control.assetInfo = CAssetCoinInfo(nAsset, nMaximumAmountAsset);
    coin_control.m_min_depth = 1;
    std::vector<COutput> vecOutputs;
    pwallet->AvailableCoins(vecOutputs, true, &coin_control, 0, MAX_MONEY, 0, nMinimumAmountAsset, nMaximumAmountAsset, nMinimumSumAmountAsset, 0, false, *coin_control.assetInfo, nVersionIn);
    int nNumOutputsFound = 0;
    int nFoundOutput = -1;
    for(unsigned int i = 0; i < vecOutputs.size(); i++) {
        if(!vecOutputs[i].fSpendable || !vecOutputs[i].fSolvable)
            continue;
        nNumOutputsFound++;
        nFoundOutput = i;
    }
    if(nNumOutputsFound > 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Too many inputs found for this asset, should only have exactly one input");
    }
    if(nNumOutputsFound <= 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "No inputs found for this asset");
    }
    
    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }
    const CInputCoin &inputCoin = vecOutputs[nFoundOutput].GetInputCoin();
    const CAmount &nGas = inputCoin.effective_value;  
    // subtract fee from this output (it should pay the gas which was funded by asset new)
    CRecipient recp = { CScript(), 0, false };
    if(recpIn) {
        vecSend.push_back(*recpIn);
    }
    if(!recpIn || nGas > (MIN_CHANGE + pwallet->m_default_max_tx_fee)) {
        CTxDestination dest;
        std::string errorStr;
        if (!pwallet->GetNewChangeDestination(pwallet->m_default_address_type, dest, errorStr)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, errorStr);
        }
        recp = { GetScriptForDestination(dest), nGas, false};  
    }
    // if enough for change + max fee, we try to take fee from this output
    if(nGas > (MIN_CHANGE + pwallet->m_default_max_tx_fee)) {
        recp.fSubtractFeeFromAmount = true;
        CAmount nTotalOther = 0;
        // deduct other sys amounts from this output which will pay the outputs and fees
        for(const auto& recipient: vecSend) {
            nTotalOther += recipient.nAmount;
        }
        // if adding other outputs would make this output not have enough to pay the fee, don't sub fee from amount
        if(nTotalOther >= (nGas - (MIN_CHANGE + pwallet->m_default_max_tx_fee)))
            recp.fSubtractFeeFromAmount = false;
        else
            recp.nAmount -= nTotalOther;
    }
    // order matters here as vecSend is in sync with asset commitment, it may change later when
    // change is added but it will resync the commitment there
    if(recp.nAmount > 0)
        vecSend.push_back(recp);
    vecSend.push_back(opreturnRecipient);
    CAmount nFeeRequired = 0;
    bilingual_str error;
    int nChangePosRet = -1;
    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
    coin_control.Select(inputCoin.outpoint);
    coin_control.fAllowOtherInputs = recp.nAmount <= 0 || !recp.fSubtractFeeFromAmount; // select asset + sys utxo's
    CTransactionRef tx;
    FeeCalculation fee_calc_out;
    if (!pwallet->CreateTransaction(vecSend, tx, nFeeRequired, nChangePosRet, error, coin_control, fee_calc_out, true /* sign*/, nVersionIn)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, error.original);
    }
    std::string err_string;
    AssertLockNotHeld(cs_main);
    NodeContext& node = EnsureNodeContext(context);
    const TransactionError err = BroadcastTransaction(node, tx, err_string, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), /*relay*/ true, /*wait_callback*/ false);
    if (TransactionError::OK != err) {
        throw JSONRPCTransactionError(err, err_string);
    }
    UniValue res(UniValue::VOBJ);
    res.__pushKV("txid", tx->GetHash().GetHex());
    return res;
}

static RPCHelpMan assetupdate()
{
    return RPCHelpMan{"assetupdate",
        "\nPerform an update on an asset you control.\n",
        {
            {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset guid"},
            {"description", RPCArg::Type::STR, RPCArg::Optional::NO, "Public description of the token."},
            {"contract",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Ethereum token contract for SyscoinX bridge. Leave empty for no smart contract bridge."},
            {"updatecapability_flags", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Ability to update certain fields. Must be decimal value which is a bitmask for certain rights to update. The bitmask 1 represents the ability to update public data field, 2 for updating the smart contract field, 4 for updating supply, 8 for updating notary address, 16 for updating notary details, 32 for updating auxfee details, 64 for ability to update the capability flags (this field). 127 for all. 0 for none (not updatable)."},
            {"notary_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Notary address"},
            {"notary_details", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Notary details structure (if notary_address is set)",
                {
                    {"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "Notary API endpoint (if applicable)"},
                    {"instant_transfers", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Enforced double-spend prevention on Notary for Instant Transfers"},
                    {"hd_required", RPCArg::Type::BOOL, RPCArg::Optional::NO, "If Notary requires HD Wallet approval (for sender approval specifically applicable to change address schemes), usually in the form of account XPUB or Verifiable Credential of account XPUB using DID"},  
                }
            },
            {"auxfee_details", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Auxiliary fee structure (may be enforced if notary is set)",
                {
                    {"auxfee_address", RPCArg::Type::STR, RPCArg::Optional::NO, "AuxFee address"},
                    {"fee_struct", RPCArg::Type::ARR, RPCArg::Optional::NO, "Auxiliary fee structure",
                        {
                            {"", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Bound (in amount) for for the fee level based on total transaction amount"},
                            {"", RPCArg::Type::NUM, RPCArg::Optional::NO, "The percentage in %% to share with the operator. The value must be\n"
                                        "between 0.00(0%%) and 0.65535(65.535%%)."},
                        },
                    }
                }
            }
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"}
            }},
        RPCExamples{
            HelpExampleCli("assetupdate", "\"asset_guid\" \"description\" \"contract\" \"updatecapability_flags\" \"notary_address\" {} {}")
            + HelpExampleRpc("assetupdate", "\"asset_guid\", \"description\", \"contract\", \"updatecapability_flags\", \"notary_address\", {}, {}")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if(!fAssetIndex) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Must specify -assetindex to be able to spend assets");
    }
    const UniValue &params = request.params;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);    
    EnsureWalletIsUnlocked(pwallet);
    const uint64_t &nBaseAsset = GetBaseAssetID(params[0].get_uint64());
    std::string strData = "";
    std::string strCategory = "";
    std::string strPubData = params[1].get_str();
    if(strPubData == "''")
        strPubData.clear();
    std::string strContract = params[2].get_str();
    if(strContract == "''")
        strContract.clear();
    if(!strContract.empty())
        boost::erase_all(strContract, "0x");  // strip 0x if exist
    std::vector<unsigned char> vchContract = ParseHex(strContract);
    
    
    CAsset theAsset;

    if (!GetAsset( nBaseAsset, theAsset))
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");
    
    
    const std::string oldData = theAsset.strPubData;
    const std::vector<unsigned char> oldContract(theAsset.vchContract);
    const std::vector<unsigned char> vchOldNotaryKeyID(theAsset.vchNotaryKeyID);
    const CNotaryDetails oldNotaryDetails = theAsset.notaryDetails;
    const CAuxFeeDetails oldAuxFeeDetails = theAsset.auxFeeDetails;
    const uint8_t nOldUpdateCapabilityFlags = theAsset.nUpdateCapabilityFlags;
    uint8_t nUpdateCapabilityFlags = nOldUpdateCapabilityFlags;
    if(!params[3].isNull())
        nUpdateCapabilityFlags = (uint8_t)params[3].get_uint();
    theAsset.ClearAsset();
    UniValue publicData(UniValue::VOBJ);
    publicData.pushKV("desc", EncodeBase64(strPubData));
    std::vector<unsigned char> vchNotaryKeyID = vchOldNotaryKeyID;
    if(!params[4].isNull()) {
        std::string strNotary = params[4].get_str();
        if(!strNotary.empty()) {
            CTxDestination txDest = DecodeDestination(strNotary);
            if (!IsValidDestination(txDest)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Invalid notary address");
            }
            if (auto witness_id = std::get_if<WitnessV0KeyHash>(&txDest)) {	
                CKeyID keyID = ToKeyID(*witness_id);
                vchNotaryKeyID = std::vector<unsigned char>(keyID.begin(), keyID.end());
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Invalid notary address: Please use P2PWKH address.");
            }
        }
    }
    uint8_t nUpdateMask = 0;
    CNotaryDetails notaryDetails(params[5]);
    CAuxFeeDetails auxFeeDetails(params[6], theAsset.nPrecision);
    strPubData = publicData.write();
    if(strPubData != oldData) {
        nUpdateMask |= ASSET_UPDATE_DATA;
        theAsset.strPrevPubData = oldData;
        theAsset.strPubData = strPubData;
    }

    if(vchContract != oldContract) {
        nUpdateMask |= ASSET_UPDATE_CONTRACT;
        theAsset.vchPrevContract = oldContract;
        theAsset.vchContract = vchContract;
    }

    if(vchNotaryKeyID != vchOldNotaryKeyID) {
        nUpdateMask |= ASSET_UPDATE_NOTARY_KEY;
        theAsset.vchPrevNotaryKeyID = vchOldNotaryKeyID;
        theAsset.vchNotaryKeyID = vchNotaryKeyID;
    }

    if(notaryDetails != oldNotaryDetails) {
        nUpdateMask |= ASSET_UPDATE_NOTARY_DETAILS;
        theAsset.prevNotaryDetails = oldNotaryDetails;
        theAsset.notaryDetails = notaryDetails;
    }

    if(auxFeeDetails != oldAuxFeeDetails) {
        nUpdateMask |= ASSET_UPDATE_AUXFEE;
        theAsset.prevAuxFeeDetails = oldAuxFeeDetails;
        theAsset.auxFeeDetails = auxFeeDetails;
    }
    if(nUpdateCapabilityFlags != nOldUpdateCapabilityFlags) {
        nUpdateMask |= ASSET_UPDATE_CAPABILITYFLAGS;
        theAsset.nPrevUpdateCapabilityFlags = nOldUpdateCapabilityFlags;
        theAsset.nUpdateCapabilityFlags = nUpdateCapabilityFlags;
    }
    theAsset.nUpdateMask = nUpdateMask;
    std::vector<CAssetOutValue> outVec = {CAssetOutValue(0, 0)};
    theAsset.voutAssets.emplace_back(CAssetOut(nBaseAsset, outVec));
    std::vector<unsigned char> data;
    theAsset.SerializeData(data);
    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient opreturnRecipient;
    CreateFeeRecipient(scriptData, opreturnRecipient);
    std::vector<CRecipient> vecSend;
    return CreateAssetUpdateTx(request.context, SYSCOIN_TX_VERSION_ASSET_UPDATE, nBaseAsset, pwallet, vecSend, opreturnRecipient);
},
    };
} 

static RPCHelpMan assettransfer()
{
    return RPCHelpMan{"assettransfer",
        "\nPerform a transfer of ownership on an asset you control.\n",
        {
            {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset guid"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "New owner of asset."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }},
        RPCExamples{
            HelpExampleCli("assettransfer", "\"asset_guid\" \"address\"")
            + HelpExampleRpc("assettransfer", "\"asset_guid\", \"address\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if(!fAssetIndex) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Must specify -assetindex to be able to spend assets");
    }
    const UniValue &params = request.params;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);    
    EnsureWalletIsUnlocked(pwallet);
    const uint64_t &nBaseAsset = GetBaseAssetID(params[0].get_uint64());
    std::string strAddress = params[1].get_str();
   
    CAsset theAsset;

    if (!GetAsset( nBaseAsset, theAsset)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");
    }
    const CScript& scriptPubKey = GetScriptForDestination(DecodeDestination(strAddress));
    CTxOut change_prototype_txout(0, scriptPubKey);
    CRecipient recp = {scriptPubKey, GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet)), false };
    theAsset.ClearAsset();
    std::vector<CAssetOutValue> outVec = {CAssetOutValue(0, 0)};
    theAsset.voutAssets.emplace_back(CAssetOut(nBaseAsset, outVec));

    std::vector<unsigned char> data;
    theAsset.SerializeData(data);
    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient opreturnRecipient;
    CreateFeeRecipient(scriptData, opreturnRecipient);
    std::vector<CRecipient> vecSend;
    return CreateAssetUpdateTx(request.context, SYSCOIN_TX_VERSION_ASSET_UPDATE, nBaseAsset, pwallet, vecSend, opreturnRecipient, &recp);
},
    };
}

static RPCHelpMan assetsendmany()
{
    return RPCHelpMan{"assetsendmany",
    "\nSend an asset you own to another address/addresses as an asset allocation. Maximum recipients is 250.\n",
    {
        {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset guid."},
        {"amounts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of asset send objects.",
            {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::NO, "An assetsend obj",
                    {
                        {"address", RPCArg::Type::NUM, RPCArg::Optional::NO, "Address to transfer to"},
                        {"asset_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to send"},
                        {"sys_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount of Syscoin to send"},
                        {"NFTID", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional NFT ID to send"},
                    }
                }
            },
            "[assetsendobjects,...]"
        }
    },
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
        }},
    RPCExamples{
        HelpExampleCli("assetsendmany", "\"asset_guid\" '[{\"address\":\"sysaddress1\",\"amount\":100},{\"address\":\"sysaddress2\",\"amount\":200}]\'")
        + HelpExampleCli("assetsendmany", "\"asset_guid\" \"[{\\\"address\\\":\\\"sysaddress1\\\",\\\"amount\\\":100},{\\\"address\\\":\\\"sysaddress2\\\",\\\"amount\\\":200}]\"")
        + HelpExampleRpc("assetsendmany", "\"asset_guid\",\'[{\"address\":\"sysaddress1\",\"amount\":100},{\"address\":\"sysaddress2\",\"amount\":200}]\'")
        + HelpExampleRpc("assetsendmany", "\"asset_guid\",\"[{\\\"address\\\":\\\"sysaddress1\\\",\\\"amount\\\":100},{\\\"address\\\":\\\"sysaddress2\\\",\\\"amount\\\":200}]\"")
    },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if(!fAssetIndex) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Must specify -assetindex to be able to spend assets");
    }    
    const UniValue &params = request.params;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    // gather & validate inputs
    const uint64_t &nAsset = params[0].get_uint64();
    const uint32_t &nBaseAsset = GetBaseAssetID(nAsset);
    UniValue valueTo = params[1];
    if (!valueTo.isArray())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Array of receivers not found");

    CAsset theAsset;
    if (!GetAsset(nBaseAsset, theAsset))
        throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");


    CAssetAllocation theAssetAllocation;
    UniValue receivers = valueTo.get_array();
    std::vector<CRecipient> vecSend;
    std::vector<CAssetOutValue> vecOut;
    std::map<uint64_t, std::pair<CAmount, CAmount> > mapAssets;
    for (unsigned int idx = 0; idx < receivers.size(); idx++) {
        const UniValue& receiver = receivers[idx];
        if (!receiver.isObject())
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"asset_guid\", \"address\", \"amount\"}");
        const UniValue &receiverObj = receiver.get_obj();
        const std::string &toStr = find_value(receiverObj, "address").get_str(); 
        const auto& dest = DecodeDestination(toStr);
        if(!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Invalid destination address %s", toStr));
        }
        const UniValue &NFTIDObj = find_value(receiverObj, "NFTID");
        uint32_t nNFTID = 0;
        if(!NFTIDObj.isNull())
            nNFTID = NFTIDObj.get_uint();
        // assign any NFTID and base asset guid into a 64 bit asset GUID which is stored and serialized
        const uint64_t &nAssetReceiver = CreateAssetID(nNFTID, nBaseAsset);
        
        const CScript& scriptPubKey = GetScriptForDestination(dest);           
        CAmount nAmount = AssetAmountFromValue(find_value(receiverObj, "amount"), theAsset.nPrecision);
        const UniValue &gasObj = find_value(receiverObj, "sys_amount");
        CAmount nAmountSys = 0;
        if(!gasObj.isNull())
            nAmountSys = AmountFromValue(gasObj);
        if(nAmount > 0 || nAmountSys <= 0) {
            auto it = std::find_if( theAssetAllocation.voutAssets.begin(), theAssetAllocation.voutAssets.end(), [&nAssetReceiver](const CAssetOut& element){ return element.key == nAssetReceiver;} );
            if(it == theAssetAllocation.voutAssets.end()) {
                theAssetAllocation.voutAssets.emplace_back(CAssetOut(nAssetReceiver, vecOut));
                it = std::find_if( theAssetAllocation.voutAssets.begin(), theAssetAllocation.voutAssets.end(), [&nAssetReceiver](const CAssetOut& element){ return element.key == nAssetReceiver;} );
            }
            it->values.push_back(CAssetOutValue(vecSend.size(), nAmount));
        }
        CTxOut change_prototype_txout(0, scriptPubKey);
        if(nAmountSys <= 0)
            nAmountSys = GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet));
        CRecipient recp = { scriptPubKey, nAmountSys, false};
        vecSend.push_back(recp);
        auto itAsset = mapAssets.emplace(nAssetReceiver, std::make_pair(nAmountSys, nAmount));
        if(!itAsset.second) {
            itAsset.first->second.first += nAmountSys;
            itAsset.first->second.second += nAmount;
        }
    }
    auto it = std::find_if( theAssetAllocation.voutAssets.begin(), theAssetAllocation.voutAssets.end(), [&nBaseAsset](const CAssetOut& element){ return element.key == nBaseAsset;} );
    if(it == theAssetAllocation.voutAssets.end()) {
        theAssetAllocation.voutAssets.emplace_back(CAssetOut(nBaseAsset, vecOut));
        it = std::find_if( theAssetAllocation.voutAssets.begin(), theAssetAllocation.voutAssets.end(), [&nBaseAsset](const CAssetOut& element){ return element.key == nBaseAsset;} );
    }
    // add change for asset
    it->values.push_back(CAssetOutValue(vecSend.size(), 0));
    CScript scriptPubKey;
    std::vector<unsigned char> data;
    theAssetAllocation.SerializeData(data);

    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient opreturnRecipient;
    CreateFeeRecipient(scriptData, opreturnRecipient);
    UniValue ret = CreateAssetUpdateTx(request.context, SYSCOIN_TX_VERSION_ASSET_SEND, nBaseAsset, pwallet, vecSend, opreturnRecipient);
    ret.__pushKV("assets_issued_count", (int)mapAssets.size());
    UniValue assetsArr(UniValue::VARR);
    for(auto itAsset: mapAssets) {
        UniValue assetsObj(UniValue::VOBJ);
        const uint64_t &nAsset = itAsset.first;
        const uint32_t &nBaseAsset = GetBaseAssetID(nAsset);
        const CAmount &nAmountSys = itAsset.second.first;
        const CAmount &nAmount = itAsset.second.second;
        assetsObj.__pushKV("asset_guid", nAsset);
        if(nBaseAsset != nAsset) {
            assetsObj.__pushKV("base_asset_guid", nBaseAsset);
            assetsObj.__pushKV("NFTID", GetNFTID(nAsset));
        }
        assetsObj.__pushKV("amount", ValueFromAssetAmount(nAmount, theAsset.nPrecision));
            assetsObj.__pushKV("sys_amount", ValueFromAmount(nAmountSys));
        assetsArr.push_back(assetsObj);
    }
    ret.__pushKV("assets_issued", assetsArr);
    return ret;
},
    };
}

static RPCHelpMan assetsend()
{
    return RPCHelpMan{"assetsend",
    "\nSend an asset you own to another address.\n",
    {
        {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "The asset guid."},
        {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the asset to (creates an asset allocation)."},
        {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to send."},
        {"sys_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount of syscoin to send."},
        {"NFTID", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional NFT ID to send"},
    },
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
        }},
    RPCExamples{
        HelpExampleCli("assetsend", "\"asset_guid\" \"address\" \"amount\" \"sys_amount\" \"NFTID\"")
        + HelpExampleRpc("assetsend", "\"asset_guid\", \"address\", \"amount\",  \"sys_amount\", \"NFTID\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if(!fAssetIndex) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Must specify -assetindex to be able to spend assets");
    }
    const UniValue &params = request.params;
    const uint64_t &nAsset = params[0].get_uint64();          
    UniValue output(UniValue::VARR);
    UniValue outputObj(UniValue::VOBJ);
    outputObj.__pushKV("address", params[1].get_str());
    outputObj.__pushKV("amount", request.params[2]);
    outputObj.__pushKV("sys_amount", request.params[3]);
    outputObj.__pushKV("NFTID", request.params[4]);
    output.push_back(outputObj);
    UniValue paramsFund(UniValue::VARR);
    paramsFund.push_back(nAsset);
    paramsFund.push_back(output);
    JSONRPCRequest requestMany(request.context);
    requestMany.params = paramsFund;
    requestMany.URI = request.URI;
    return assetsendmany().HandleRequest(requestMany);          
},
    };
}

static RPCHelpMan assetallocationsendmany()
{
    return RPCHelpMan{"assetallocationsendmany",
        "\nSend an asset allocation you own to another address. Maximum recipients is 250.\n",
        {
            {"amounts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of assetallocationsend objects",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "The assetallocationsend object",
                        {
                            {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset guid"},
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Address to transfer to"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to send"},
                            {"sys_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount of Syscoin to send"},
                        }
                    },
                    },
                    "[assetallocationsend object]..."
            },
            {"replaceable", RPCArg::Type::BOOL, /* default */ "wallet default", "Allow this transaction to be replaced by a transaction with higher fees via BIP 125. ZDAG is only possible if RBF is disabled."},
            {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "A comment"},
            {"conf_target", RPCArg::Type::NUM, /* default */ "wallet default", "Confirmation target (in blocks)"},
            {"estimate_mode", RPCArg::Type::STR, /* default */ "UNSET", "The fee estimate mode, must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\""},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }},
        RPCExamples{
            HelpExampleCli("assetallocationsendmany", "\'[{\"asset_guid\":1045909988,\"address\":\"sysaddress1\",\"amount\":100},{\"asset_guid\":1045909988,\"address\":\"sysaddress2\",\"amount\":200}]\' \"false\"")
            + HelpExampleCli("assetallocationsendmany", "\"[{\\\"asset_guid\\\":1045909988,\\\"address\\\":\\\"sysaddress1\\\",\\\"amount\\\":100},{\\\"asset_guid\\\":1045909988,\\\"address\\\":\\\"sysaddress2\\\",\\\"amount\\\":200}]\" \"true\"")
            + HelpExampleRpc("assetallocationsendmany", "\'[{\"asset_guid\":1045909988,\"address\":\"sysaddress1\",\"amount\":100},{\"asset_guid\":1045909988,\"address\":\"sysaddress2\",\"amount\":200}]\',\"false\"")
            + HelpExampleRpc("assetallocationsendmany", "\"[{\\\"asset_guid\\\":1045909988,\\\"address\\\":\\\"sysaddress1\\\",\\\"amount\\\":100},{\\\"asset_guid\\\":1045909988,\\\"address\\\":\\\"sysaddress2\\\",\\\"amount\\\":200}]\",\"true\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if(!fAssetIndex) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Must specify -assetindex to be able to spend assets");
    }
	const UniValue &params = request.params;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    CCoinControl coin_control;
	// gather & validate inputs
	UniValue valueTo = params[0];
	if (!valueTo.isArray())
		throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Array of receivers not found");
    bool m_signal_bip125_rbf = pwallet->m_signal_rbf;
    if (!request.params[1].isNull()) {
        m_signal_bip125_rbf = request.params[1].get_bool();
    }
    mapValue_t mapValue;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty())
        mapValue["comment"] = request.params[2].get_str();
    if (!request.params[3].isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[3], pwallet->chain().estimateMaxBlocks());
    }
    if (!request.params[4].isNull()) {
        if (!FeeModeFromString(request.params[4].get_str(), coin_control.m_fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
    }
    CAssetAllocation theAssetAllocation;
    CMutableTransaction mtx;
	UniValue receivers = valueTo.get_array();
    std::map<uint64_t, std::pair<CAmount,CAmount> > mapAssets;
    std::vector<CAssetOutValue> vecOut;
    uint8_t bOverideRBF = 0;
	for (unsigned int idx = 0; idx < receivers.size(); idx++) {
        CAmount nTotalSending = 0;
		const UniValue& receiver = receivers[idx];
		if (!receiver.isObject())
			throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"address\" or \"amount\"}");

		const UniValue &receiverObj = receiver.get_obj();
        const uint64_t &nAsset = find_value(receiverObj, "asset_guid").get_uint64();
        const uint32_t &nBaseAsset = GetBaseAssetID(nAsset);
        CAsset theAsset;
        if (!GetAsset(nBaseAsset, theAsset))
            throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");
        // override RBF if one notarized asset has it enabled
        if(!bOverideRBF && !theAsset.vchNotaryKeyID.empty() && !theAsset.notaryDetails.IsNull()) {
            bOverideRBF = theAsset.notaryDetails.bEnableInstantTransfers;
        }

        const std::string &toStr = find_value(receiverObj, "address").get_str();
        const auto& dest = DecodeDestination(toStr);
        if(!IsValidDestination(dest)) 
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Invalid destination address %s", toStr));
        const CScript& scriptPubKey = GetScriptForDestination(dest);   
        CTxOut change_prototype_txout(0, scriptPubKey);
        const CAmount &nAmount = AssetAmountFromValue(find_value(receiverObj, "amount"), theAsset.nPrecision);
        const UniValue &gasObj = find_value(receiverObj, "sys_amount");
        CAmount nAmountSys = 0;
        if(!gasObj.isNull())
            nAmountSys = AmountFromValue(gasObj);
        if(nAmount > 0 || nAmountSys <= 0) {
            auto itVout = std::find_if( theAssetAllocation.voutAssets.begin(), theAssetAllocation.voutAssets.end(), [&nAsset](const CAssetOut& element){ return element.key == nAsset;} );
            if(itVout == theAssetAllocation.voutAssets.end()) {
                CAssetOut assetOut(nAsset, vecOut);
                if(!theAsset.vchNotaryKeyID.empty()) {
                    // fund tx expecting 65 byte signature to be filled in
                    assetOut.vchNotarySig.resize(65);
                }
                theAssetAllocation.voutAssets.emplace_back(assetOut);
                itVout = std::find_if( theAssetAllocation.voutAssets.begin(), theAssetAllocation.voutAssets.end(), [&nAsset](const CAssetOut& element){ return element.key == nAsset;} );
            }
            itVout->values.push_back(CAssetOutValue(mtx.vout.size(), nAmount));
        }
        if(nAmountSys <= 0)
            nAmountSys = GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet));
        CRecipient recp = { scriptPubKey, nAmountSys, false};
        mtx.vout.push_back(CTxOut(recp.nAmount, recp.scriptPubKey));
        auto itAsset = mapAssets.emplace(nAsset, std::make_pair(nAmountSys, nAmount));
        if(!itAsset.second) {
            itAsset.first->second.first += nAmountSys;
            itAsset.first->second.second += nAmount;
        }
        nTotalSending += nAmount;
	        
    }
    // if all instant transfers using notary, we use RBF
    if(bOverideRBF) {
        // only override if parameter was not provided by user
        if(request.params[1].isNull())
            m_signal_bip125_rbf = true;
    }
    // aux fees if applicable
    for(const auto &it: mapAssets) {
        const uint64_t &nAsset = it.first;
        const uint32_t &nBaseAsset = GetBaseAssetID(nAsset);
        CAsset theAsset;
        if (!GetAsset(nBaseAsset, theAsset))
            throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");
        CAmount nAuxFee;
        getAuxFee(theAsset.auxFeeDetails, it.second.second, nAuxFee);
        if(nAuxFee > 0 && !theAsset.auxFeeDetails.vchAuxFeeKeyID.empty()){
            auto itVout = std::find_if( theAssetAllocation.voutAssets.begin(), theAssetAllocation.voutAssets.end(), [&nAsset](const CAssetOut& element){ return element.key == nAsset;} );
            if(itVout == theAssetAllocation.voutAssets.end()) {
                 throw JSONRPCError(RPC_DATABASE_ERROR, "Invalid asset not found in voutAssets");
            }
            itVout->values.push_back(CAssetOutValue(mtx.vout.size(), nAuxFee));
            const CScript& scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(uint160{theAsset.auxFeeDetails.vchAuxFeeKeyID}));
            CTxOut change_prototype_txout(0, scriptPubKey);
            CAmount nAmountSys = GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet));
            CRecipient recp = {scriptPubKey, nAmountSys, false };
            mtx.vout.push_back(CTxOut(recp.nAmount, recp.scriptPubKey));
            auto it = mapAssets.try_emplace(nAsset, std::make_pair(nAmountSys, nAuxFee));
            if(!it.second) {
                it.first->second.first += nAmountSys;
                it.first->second.second += nAuxFee;
            }
        }
    }
    coin_control.m_signal_bip125_rbf = m_signal_bip125_rbf;
    EnsureWalletIsUnlocked(pwallet);

	std::vector<unsigned char> data;
	theAssetAllocation.SerializeData(data);   


	CScript scriptData;
	scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fee);
    mtx.vout.push_back(CTxOut(fee.nAmount, fee.scriptPubKey));
    CAmount nFeeRequired = 0;
    bilingual_str error;
    int nChangePosRet = -1;
    bool lockUnspents = false;
    std::set<int> setSubtractFeeFromOutputs;
    // if zdag double the fee rate
    if(coin_control.m_signal_bip125_rbf == false) {
        CFeeRate rate = pwallet->chain().relayMinFee();
        rate += pwallet->chain().relayMinFee();
        coin_control.m_feerate = rate;
    }
    mtx.nVersion = SYSCOIN_TX_VERSION_ALLOCATION_SEND;
    for(const auto &it: mapAssets) {
        nChangePosRet = -1;
        nFeeRequired = 0;
        coin_control.assetInfo = CAssetCoinInfo(it.first, it.second.second);
        if (!pwallet->FundTransaction(mtx, nFeeRequired, nChangePosRet, error, lockUnspents, setSubtractFeeFromOutputs, coin_control)) {
            throw JSONRPCError(RPC_WALLET_ERROR, error.original);
        }
    }
    if(pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        UniValue result(UniValue::VOBJ);
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, false /* sign */, true /* bip32derivs */);
        CHECK_NONFATAL(err == TransactionError::OK);
        CHECK_NONFATAL(!complete);
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        return result;
    }
    // Script verification errors
    std::map<int, std::string> input_errors;
    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    pwallet->chain().findCoins(coins);
    bool complete = pwallet->SignTransaction(mtx, coins, SIGHASH_ALL, input_errors);
    if(!complete) {
        UniValue result(UniValue::VOBJ);
        SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
        return result;
    }
    // need to reload asset as notary signature may have gotten added and this is needed in voutAssets so consensus validation passes for notary check
    mtx.LoadAssets();
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    std::string err_string;
    AssertLockNotHeld(cs_main);
    NodeContext& node = EnsureNodeContext(request.context);
    const TransactionError err = BroadcastTransaction(node, tx, err_string, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), /*relay*/ true, /*wait_callback*/ false);
    if (TransactionError::OK != err) {
        throw JSONRPCTransactionError(err, err_string);
    }
    UniValue ret(UniValue::VOBJ);
    ret.__pushKV("txid", tx->GetHash().GetHex());
    ret.__pushKV("assetallocations_sent_count", (int)mapAssets.size());
    UniValue assetsArr(UniValue::VARR);
    for(auto itAsset: mapAssets) {
        UniValue assetsObj(UniValue::VOBJ);
        const uint64_t &nAsset = itAsset.first;
        const uint32_t &nBaseAsset = GetBaseAssetID(nAsset);
        CAsset theAsset;
        if (!GetAsset(nBaseAsset, theAsset))
            throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");
        const CAmount &nAmountSys = itAsset.second.first;
        const CAmount &nAmount = itAsset.second.second;
        assetsObj.__pushKV("asset_guid", nAsset);
        if(nBaseAsset != nAsset) {
            assetsObj.__pushKV("base_asset_guid", nBaseAsset);
            assetsObj.__pushKV("NFTID", GetNFTID(nAsset));
        }
        assetsObj.__pushKV("amount", ValueFromAssetAmount(nAmount, theAsset.nPrecision));
            assetsObj.__pushKV("sys_amount", ValueFromAmount(nAmountSys));
        assetsArr.push_back(assetsObj);
    }
    ret.__pushKV("assetallocations_sent", assetsArr);
    return ret;
},
    };
}

static RPCHelpMan assetallocationburn()
{
    return RPCHelpMan{"assetallocationburn",
        "\nBurn an asset allocation in order to use the bridge or move back to Syscoin\n",
        {
            {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset guid"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to burn to SYSX"},
            {"ethereum_destination_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The 20 byte (40 character) hex string of the ethereum destination address. Omit or leave empty to burn to Syscoin."}
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }},
        RPCExamples{
            HelpExampleCli("assetallocationburn", "\"asset_guid\" \"amount\" \"ethereum_destination_address\"")
            + HelpExampleRpc("assetallocationburn", "\"asset_guid\", \"amount\", \"ethereum_destination_address\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if(!fAssetIndex) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Must specify -assetindex to be able to spend assets");
    }    
	const UniValue &params = request.params;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    const uint64_t &nAsset = params[0].get_uint64();
    	
	CAsset theAsset;
	if (!GetAsset(GetBaseAssetID(nAsset), theAsset))
		throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");
        
    CAmount nAmount;
    try{
        nAmount = AssetAmountFromValue(params[1], theAsset.nPrecision);
    }
    catch(...) {
        nAmount = params[1].get_int64();
    }
	std::string ethAddress = "";
    if(params[2].isStr())
        ethAddress = params[2].get_str();
    boost::erase_all(ethAddress, "0x");  // strip 0x if exist
    CScript scriptData;
    int32_t nVersionIn = 0;

    CBurnSyscoin burnSyscoin;
    int nChangePosRet = 1; 
    // if no eth address provided just send as a std asset allocation send but to burn address
    if(ethAddress.empty() || ethAddress == "''") {
        nVersionIn = SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN;
        std::vector<CAssetOutValue> vecOut = {CAssetOutValue(1, nAmount)}; // burn has to be in index 1, sys is output in index 0, any change in index 2
        CAssetOut assetOut(nAsset, vecOut);
        if(!theAsset.vchNotaryKeyID.empty()) {
            assetOut.vchNotarySig.resize(65);  
        }
        burnSyscoin.voutAssets.emplace_back(assetOut);
        nChangePosRet++;
    }
    else {
        burnSyscoin.vchEthAddress = ParseHex(ethAddress);
        nVersionIn = SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_ETHEREUM;
        std::vector<CAssetOutValue> vecOut = {CAssetOutValue(0, nAmount)}; // burn has to be in index 0, any change in index 1
        CAssetOut assetOut(nAsset, vecOut);
        if(!theAsset.vchNotaryKeyID.empty()) {
            assetOut.vchNotarySig.resize(65);  
        }
        burnSyscoin.voutAssets.emplace_back(assetOut);
    }
    
    CTxDestination dest;
    std::string errorStr;
    if (!pwallet->GetNewChangeDestination(pwallet->m_default_address_type, dest, errorStr)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, errorStr);
    }

    const CScript& scriptPubKey = GetScriptForDestination(dest);
    CRecipient recp = {scriptPubKey, nAmount, false };

    std::vector<unsigned char> data;
    burnSyscoin.SerializeData(data);  
    scriptData << OP_RETURN << data;
	CRecipient fee;
	CreateFeeRecipient(scriptData, fee);
    CMutableTransaction mtx;
    // output to new sys output
    if(nVersionIn == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN)
        mtx.vout.push_back(CTxOut(recp.nAmount, recp.scriptPubKey));
    // burn output
    mtx.vout.push_back(CTxOut(fee.nAmount, fee.scriptPubKey));

    CAmount nFeeRequired = 0;
    bool lockUnspents = false;
    std::set<int> setSubtractFeeFromOutputs;
    bilingual_str error;
    mtx.nVersion = nVersionIn;
    CCoinControl coin_control;
    coin_control.assetInfo = CAssetCoinInfo(nAsset, nAmount);
    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
    if (!pwallet->FundTransaction(mtx, nFeeRequired, nChangePosRet, error, lockUnspents, setSubtractFeeFromOutputs, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }
    if(pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        UniValue result(UniValue::VOBJ);
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, false /* sign */, true /* bip32derivs */);
        CHECK_NONFATAL(err == TransactionError::OK);
        CHECK_NONFATAL(!complete);
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        return result;
    }
    // Script verification errors
    std::map<int, std::string> input_errors;
    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    pwallet->chain().findCoins(coins);
    bool complete = pwallet->SignTransaction(mtx, coins, SIGHASH_ALL, input_errors);
    if(!complete) {
        UniValue result(UniValue::VOBJ);
        SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
        return result;
    }
    // need to reload asset as notary signature may have gotten added and this is needed in voutAssets so consensus validation passes for notary check
    mtx.LoadAssets();
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    std::string err_string;
    AssertLockNotHeld(cs_main);
    NodeContext& node = EnsureNodeContext(request.context);
    const TransactionError err = BroadcastTransaction(node, tx, err_string, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), /*relay*/ true, /*wait_callback*/ false);
    if (TransactionError::OK != err) {
        throw JSONRPCTransactionError(err, err_string);
    }

    UniValue res(UniValue::VOBJ);
    res.__pushKV("txid", tx->GetHash().GetHex());
    return res;
},
    };
}

std::vector<unsigned char> ushortToBytes(unsigned short paramShort) {
     std::vector<unsigned char> arrayOfByte(2);
     for (int i = 0; i < 2; i++)
         arrayOfByte[1 - i] = (paramShort >> (i * 8));
     return arrayOfByte;
}

static RPCHelpMan assetallocationmint()
{ 
    return RPCHelpMan{"assetallocationmint",
        "\nMint assetallocation to come back from the bridge\n",
        {
            {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset guid"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Mint to this address."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to mint.  Note that fees (in SYS) will be taken from the owner address"},
            {"blocknumber", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block number of the block that included the burn transaction on Ethereum."},
            {"bridge_transfer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unique Bridge Transfer ID for this event from Ethereum. It is the low 32 bits of the transferIdAndPrecisions field in the TokenFreeze Event on freezeBurnERC20 call."},
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction hex."},
            {"txroot_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction merkle root that commits this transaction to the block header."},
            {"txmerkleproof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The list of parent nodes of the Merkle Patricia Tree for SPV proof of transaction merkle root."},
            {"merklerootpath_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The merkle path to walk through the tree to recreate the merkle hash for both transaction and receipt root."},
            {"receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction Receipt Hex."},
            {"receiptroot_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction receipt merkle root that commits this receipt to the block header."},
            {"receiptmerkleproof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The list of parent nodes of the Merkle Patricia Tree for SPV proof of transaction receipt merkle root."},
            {"auxfee_test", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Used for internal testing only."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }},
        RPCExamples{
            HelpExampleCli("assetallocationmint", "\"asset_guid\" \"address\" \"amount\" \"blocknumber\" \"bridge_transfer_id\" \"tx_hex\" \"txroot_hex\" \"txmerkleproof_hex\" \"txmerkleproofpath_hex\" \"receipt_hex\" \"receiptroot_hex\" \"receiptmerkleproof\"")
            + HelpExampleRpc("assetallocationmint", "\"asset_guid\", \"address\", \"amount\", \"blocknumber\", \"bridge_transfer_id\", \"tx_hex\", \"txroot_hex\", \"txmerkleproof_hex\", \"txmerkleproofpath_hex\", \"receipt_hex\", \"receiptroot_hex\", \"receiptmerkleproof\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue &params = request.params;
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    const uint64_t &nAsset = params[0].get_uint64();
    std::string strAddress = params[1].get_str();
	CAsset theAsset;
	if (!GetAsset(GetBaseAssetID(nAsset), theAsset))
		throw JSONRPCError(RPC_DATABASE_ERROR, "Could not find a asset with this key");    
    CAmount nAmount;
    try{
        nAmount = AssetAmountFromValue(request.params[2], theAsset.nPrecision);
    }
    catch(...) {
        nAmount = request.params[2].get_int64();
    }        
    const uint32_t &nBlockNumber = params[3].get_uint(); 
    const uint32_t &nBridgeTransferID = params[4].get_uint(); 
    
    std::string vchTxValue = params[5].get_str();
    std::string vchTxRoot = params[6].get_str();
    std::string vchTxParentNodes = params[7].get_str();

    // find byte offset of tx data in the parent nodes
    size_t pos = vchTxParentNodes.find(vchTxValue);
    if(pos == std::string::npos || vchTxParentNodes.size() > (USHRT_MAX*2)){
        throw JSONRPCError(RPC_TYPE_ERROR, "Could not find tx value in tx parent nodes");  
    }
    uint16_t posTxValue = (uint16_t)pos/2;
    std::string vchTxPath = params[8].get_str();
 
    std::string vchReceiptValue = params[9].get_str();
    std::string vchReceiptRoot = params[10].get_str();
    std::string vchReceiptParentNodes = params[11].get_str();
    pos = vchReceiptParentNodes.find(vchReceiptValue);
    if(pos == std::string::npos || vchReceiptParentNodes.size() > (USHRT_MAX*2)){
        throw JSONRPCError(RPC_TYPE_ERROR, "Could not find receipt value in receipt parent nodes");  
    }
    uint16_t posReceiptValue = (uint16_t)pos/2;
    if(!fGethSynced){
        throw JSONRPCError(RPC_MISC_ERROR, "Geth is not synced, please wait until it syncs up and try again");
    }


    std::vector<CRecipient> vecSend;
    
    CMintSyscoin mintSyscoin;
    std::vector<CAssetOutValue> vecOut = {CAssetOutValue(0, nAmount)};
    CAssetOut assetOut(nAsset, vecOut);
    if(!theAsset.vchNotaryKeyID.empty()) {
        assetOut.vchNotarySig.resize(65);
    }
    mintSyscoin.voutAssets.emplace_back(assetOut);
    mintSyscoin.nBlockNumber = nBlockNumber;
    mintSyscoin.nBridgeTransferID = nBridgeTransferID;
    mintSyscoin.posTx = posTxValue;
    mintSyscoin.vchTxRoot = ParseHex(vchTxRoot);
    mintSyscoin.vchTxParentNodes = ParseHex(vchTxParentNodes);
    mintSyscoin.vchTxPath = ParseHex(vchTxPath);
    mintSyscoin.posReceipt = posReceiptValue;
    mintSyscoin.vchReceiptRoot = ParseHex(vchReceiptRoot);
    mintSyscoin.vchReceiptParentNodes = ParseHex(vchReceiptParentNodes);
    
    const CScript& scriptPubKey = GetScriptForDestination(DecodeDestination(strAddress));
    CTxOut change_prototype_txout(0, scriptPubKey);
    CRecipient recp = {scriptPubKey, GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet)), false };    
    
    CMutableTransaction mtx;
    mtx.nVersion = SYSCOIN_TX_VERSION_ALLOCATION_MINT;
    mtx.vout.push_back(CTxOut(recp.nAmount, recp.scriptPubKey));
    if(params.size() >= 13 && params[12].isBool() && params[12].get_bool()) {
        // aux fees test
        CAmount nAuxFee;
        getAuxFee(theAsset.auxFeeDetails, nAmount, nAuxFee);
        if(nAuxFee > 0 && !theAsset.auxFeeDetails.vchAuxFeeKeyID.empty()){
            auto itVout = std::find_if( mintSyscoin.voutAssets.begin(), mintSyscoin.voutAssets.end(), [&nAsset](const CAssetOut& element){ return element.key == nAsset;} );
            if(itVout == mintSyscoin.voutAssets.end()) {
                throw JSONRPCError(RPC_DATABASE_ERROR, "Invalid asset not found in voutAssets");
            }
            itVout->values.push_back(CAssetOutValue(mtx.vout.size(), nAuxFee));
            const CScript& scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(uint160{theAsset.auxFeeDetails.vchAuxFeeKeyID}));
            CTxOut change_prototype_txout(0, scriptPubKey);
            CRecipient recp = {scriptPubKey, GetDustThreshold(change_prototype_txout, GetDiscardRate(*pwallet)), false };
            mtx.vout.push_back(CTxOut(recp.nAmount, recp.scriptPubKey));
        }
    }
    std::vector<unsigned char> data;
    mintSyscoin.SerializeData(data);
    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient fee;
    CreateFeeRecipient(scriptData, fee);
    mtx.vout.push_back(CTxOut(fee.nAmount, fee.scriptPubKey));
    CAmount nFeeRequired = 0;
    bilingual_str error;
    int nChangePosRet = -1;
    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = pwallet->m_signal_rbf;
    bool lockUnspents = false;
    std::set<int> setSubtractFeeFromOutputs;
    if (!pwallet->FundTransaction(mtx, nFeeRequired, nChangePosRet, error, lockUnspents, setSubtractFeeFromOutputs, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }
    if(pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        UniValue result(UniValue::VOBJ);
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const TransactionError err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, false /* sign */, true /* bip32derivs */);
        CHECK_NONFATAL(err == TransactionError::OK);
        CHECK_NONFATAL(!complete);
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
        return result;
    }
    // Script verification errors
    std::map<int, std::string> input_errors;
    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    pwallet->chain().findCoins(coins);
    bool complete = pwallet->SignTransaction(mtx, coins, SIGHASH_ALL, input_errors);
    if(!complete) {
        UniValue result(UniValue::VOBJ);
        SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
        return result;
    }
    // need to reload asset as notary signature may have gotten added and this is needed in voutAssets so consensus validation passes for notary check
    mtx.LoadAssets();
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    std::string err_string;
    AssertLockNotHeld(cs_main);
    NodeContext& node = EnsureNodeContext(request.context);
    const TransactionError err = BroadcastTransaction(node, tx, err_string, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), /*relay*/ true, /*wait_callback*/ false);
    if (TransactionError::OK != err) {
        throw JSONRPCTransactionError(err, err_string);
    }
    UniValue res(UniValue::VOBJ);
    res.__pushKV("txid", tx->GetHash().GetHex());
    return res;  
},
    };
}
static RPCHelpMan assetallocationsend()
{
    return RPCHelpMan{"assetallocationsend",
        "\nSend an asset allocation you own to another address.\n",
        {
            {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "The asset guid"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the allocation to"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to send"},
            {"sys_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Amount of syscoin to send"},
            {"replaceable", RPCArg::Type::BOOL, /* default */ "wallet default", "Allow this transaction to be replaced by a transaction with higher fees via BIP 125. ZDAG is only possible if RBF is disabled."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
            }},
        RPCExamples{
            HelpExampleCli("assetallocationsend", "\"asset_guid\" \"address\" \"amount\" \"sys_amount\" \"false\"")
            + HelpExampleRpc("assetallocationsend", "\"asset_guid\", \"address\", \"amount\", \"sys_amount\", \"false\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if(!fAssetIndex) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Must specify -assetindex to be able to spend assets");
    }
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    const UniValue &params = request.params;
    const uint64_t &nAsset = params[0].get_uint64();          
    bool m_signal_bip125_rbf = pwallet->m_signal_rbf;
    if (!request.params[4].isNull()) {
        m_signal_bip125_rbf = request.params[4].get_bool();
    }  
    UniValue replaceableObj(UniValue::VBOOL);
    UniValue commentObj(UniValue::VSTR);
    UniValue confObj(UniValue::VNUM);
    UniValue feeObj(UniValue::VSTR);
    replaceableObj.setBool(m_signal_bip125_rbf);
    commentObj.setStr("");
    confObj.setInt(DEFAULT_TX_CONFIRM_TARGET);
    feeObj.setStr("UNSET");
    UniValue output(UniValue::VARR);
    UniValue outputObj(UniValue::VOBJ);
    outputObj.__pushKV("asset_guid", nAsset);
    outputObj.__pushKV("address", params[1].get_str());
    outputObj.__pushKV("amount", request.params[2]);
    outputObj.__pushKV("sys_amount", request.params[3]);
    output.push_back(outputObj);
    UniValue paramsFund(UniValue::VARR);
    paramsFund.push_back(output);
    paramsFund.push_back(replaceableObj);
    paramsFund.push_back(commentObj); // comment
    paramsFund.push_back(confObj); // conf_target
    paramsFund.push_back(feeObj); // estimate_mode
    JSONRPCRequest requestMany(request.context);
    requestMany.params = paramsFund;
    requestMany.URI = request.URI;
    return assetallocationsendmany().HandleRequest(requestMany);          
},
    };
}

static RPCHelpMan convertaddresswallet()
{
    return RPCHelpMan{"convertaddresswallet",
    "\nConvert between Syscoin 3 and Syscoin 4 formats. This should only be used with addressed based on compressed private keys only. P2WPKH can be shown as P2PKH in Syscoin 3. Adds to wallet as receiving address under label specified.",   
    {	
        {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The syscoin address to get the information of."},	
        {"label", RPCArg::Type::STR,RPCArg::Optional::NO, "Label Syscoin V4 address and store in receiving address. Set to \"\" to not add to receiving address", "An optional label"},	
        {"rescan", RPCArg::Type::BOOL, /* default */ "false", "Rescan the wallet for transactions. Useful if you provided label to add to receiving address"},	
    },	
    RPCResult{
        RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::STR, "v3address", "The syscoin 3 address validated"},
            {RPCResult::Type::STR, "v4address", "The syscoin 4 address validated"},
        },
    },		
    RPCExamples{	
        HelpExampleCli("convertaddresswallet", "\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\" \"bob\" true")	
        + HelpExampleRpc("convertaddresswallet", "\"sys1qw40fdue7g7r5ugw0epzk7xy24tywncm26hu4a7\" \"bob\" true")	
    },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    UniValue ret(UniValue::VOBJ);	
    CTxDestination dest = DecodeDestination(request.params[0].get_str());	
    std::string strLabel = "";	
    if (!request.params[1].isNull())	
        strLabel = request.params[1].get_str();    	
    bool fRescan = false;	
    if (!request.params[2].isNull())	
        fRescan = request.params[2].get_bool();	
    // Make sure the destination is valid	
    if (!IsValidDestination(dest)) {	
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");	
    }	
    std::string currentV4Address = "";	
    std::string currentV3Address = "";	
    CTxDestination v4Dest;	
    if (auto witness_id = std::get_if<WitnessV0KeyHash>(&dest)) {	
        v4Dest = dest;	
        currentV4Address =  EncodeDestination(v4Dest);	
        currentV3Address =  EncodeDestination(*witness_id);	
    }	
    else if (auto key_id = std::get_if<PKHash>(&dest)) {	
        v4Dest = WitnessV0KeyHash(*key_id);	
        currentV4Address =  EncodeDestination(v4Dest);	
        currentV3Address =  EncodeDestination(*key_id);	
    }	
    else if (auto script_id = std::get_if<ScriptHash>(&dest)) {	
        v4Dest = *script_id;	
        currentV4Address =  EncodeDestination(v4Dest);	
        currentV3Address =  currentV4Address;	
    }	
    else if (std::get_if<WitnessV0ScriptHash>(&dest)) {	
        v4Dest = dest;	
        currentV4Address =  EncodeDestination(v4Dest);	
        currentV3Address =  currentV4Address;	
    } 	
    else	
        strLabel = "";	
    LOCK(pwallet->cs_wallet);
    isminetype mine = pwallet->IsMine(v4Dest);	
    if(!(mine & ISMINE_SPENDABLE)){	
        throw JSONRPCError(RPC_MISC_ERROR, "The V4 Public key or redeemscript not known to wallet, or the key is uncompressed.");	
    }	
    if(!strLabel.empty())	
    {		
        CScript witprog = GetScriptForDestination(v4Dest);	
        LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();	
        if(spk_man)	
            spk_man->AddCScript(witprog); // Implicit for single-key now, but necessary for multisig and for compatibility	
        pwallet->SetAddressBook(v4Dest, strLabel, "receive");	
        WalletRescanReserver reserver(*pwallet);                   	
        if (fRescan) {	
            int64_t scanned_time = pwallet->RescanFromTime(0, reserver, true);	
            if (pwallet->IsAbortingRescan()) {	
                throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");	
            } else if (scanned_time > 0) {	
                throw JSONRPCError(RPC_WALLET_ERROR, "Rescan was unable to fully rescan the blockchain. Some transactions may be missing.");	
            }	
        }  	
    }	

    ret.pushKV("v3address", currentV3Address);	
    ret.pushKV("v4address", currentV4Address); 	
    return ret;	
},
    };
}


	
static RPCHelpMan listunspentasset()
{
    return RPCHelpMan{"listunspentasset",
    "\nHelper function which just calls listunspent to find unspent UTXO's for an asset.",   
    {	
        {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "The syscoin asset guid to get the information of."},	
        {"minconf", RPCArg::Type::NUM, /* default */ "1", "The minimum confirmations to filter"},	
    },	
    RPCResult{
        RPCResult::Type::STR, "result", "Result"
    },		
    RPCExamples{	
        HelpExampleCli("listunspentasset", "2328882 0")	
        + HelpExampleRpc("listunspentasset", "2328882 0")	
    },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    uint64_t nAsset = request.params[0].get_uint64();
    int nMinDepth = 1;
    if (!request.params[1].isNull()) {
        nMinDepth = request.params[1].get_int();
    }
    int nMaxDepth = 9999999;
    bool include_unsafe = true;
    UniValue paramsFund(UniValue::VARR);
    UniValue addresses(UniValue::VARR);
    UniValue includeSafe(UniValue::VBOOL);
    includeSafe.setBool(include_unsafe);
    paramsFund.push_back(nMinDepth);
    paramsFund.push_back(nMaxDepth);
    paramsFund.push_back(addresses);
    paramsFund.push_back(includeSafe);
    
    UniValue options(UniValue::VOBJ);
    options.__pushKV("assetGuid", nAsset);
    paramsFund.push_back(options);
    JSONRPCRequest requestSpent(request.context);
    requestSpent.params = paramsFund;
    requestSpent.URI = request.URI;
    return listunspent().HandleRequest(requestSpent);  
},
    };
}

static RPCHelpMan addressbalance() {
    return RPCHelpMan{"addressbalance",	
        "\nShow the Syscoin balance of an array of addresses in your wallet.\n",	
        {	
                {"addresses", RPCArg::Type::ARR, RPCArg::Optional::NO, "The syscoin addresses to filter",
                    {
                        {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "syscoin address"},
                    },
                },
                {"minconf", RPCArg::Type::NUM, /* default */ "1", "The minimum confirmations to filter"},
                {"maxconf", RPCArg::Type::NUM, /* default */ "9999999", "The maximum confirmations to filter"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "amount", "Syscoin balance of the addressn"},
            }},	
        RPCExamples{	
            HelpExampleCli("addressbalance", "\"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\" 6 9999999")
            + HelpExampleRpc("addressbalance", "\"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\", 6, 9999999")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{	
    int nMinDepth = 1;
    if (!request.params[1].isNull()) {
        nMinDepth = request.params[1].get_int();
    }
    int nMaxDepth = 9999999;
    if (!request.params[2].isNull()) {
        nMaxDepth = request.params[1].get_int();
    }
    UniValue paramsFund(UniValue::VARR);
    paramsFund.push_back(nMinDepth);
    paramsFund.push_back(nMaxDepth);
    paramsFund.push_back(request.params[0]);
    JSONRPCRequest requestSpent(request.context);
    requestSpent.params = paramsFund;
    requestSpent.URI = request.URI;
    const UniValue &resUTXOs = listunspent().HandleRequest(requestSpent);
    CAmount nTotalAmount = 0;
    const UniValue &resUTXOArr = resUTXOs.get_array();
    if(!resUTXOArr.isNull()) {
        for(size_t i =0;i<resUTXOArr.size();i++) {
            nTotalAmount += AmountFromValue(find_value(resUTXOArr[i].get_obj(), "amount"));
        }
    }
    UniValue res(UniValue::VOBJ);
    res.__pushKV("amount", ValueFromAmount(nTotalAmount));
    return res;
},
    };
}

static RPCHelpMan assetallocationbalance() {
    return RPCHelpMan{"assetallocationbalance",	
        "\nShow asset and allocated balance information pertaining to an asset owned in your wallet.\n",	
        {	
                {"asset_guid", RPCArg::Type::NUM, RPCArg::Optional::NO, "The syscoin asset guid to get the information of."},
                {"addresses", RPCArg::Type::ARR, /* default */ "empty array", "The syscoin addresses to filter",
                    {
                        {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "syscoin address"},
                    },
                },
                {"minconf", RPCArg::Type::NUM, /* default */ "1", "The minimum confirmations to filter"},
                {"maxconf", RPCArg::Type::NUM, /* default */ "9999999", "The maximum confirmations to filter"},
                {"verbose", RPCArg::Type::BOOL, /* default */ "false", "If false, return just balances, otherwise return asset information as well as balances"},
        },
        {
            RPCResult{"for verbose = false",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_AMOUNT, "amount", "the balance output amount in " + CURRENCY_UNIT},
                    {RPCResult::Type::STR_AMOUNT, "asset_amount", "the balance asset amount in satoshis"},
                }
            },
            RPCResult{"for verbose = true",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "asset_guid", "The guid of the asset"},
                    {RPCResult::Type::STR, "symbol", "The asset symbol"},
                    {RPCResult::Type::STR_HEX, "txid", "The transaction id that created this asset"},
                    {RPCResult::Type::STR, "public_value", "The public value attached to this asset"},
                    {RPCResult::Type::STR_HEX, "contract", "The ethereum contract address"},
                    {RPCResult::Type::STR_AMOUNT, "total_supply", "The total supply of this asset"},
                    {RPCResult::Type::STR_AMOUNT, "max_supply", "The maximum supply of this asset"},
                    {RPCResult::Type::NUM, "updatecapability_flags", "The capability flag in decimal"},
                    {RPCResult::Type::NUM, "precision", "The precision of this asset"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "the balance output amount in " + CURRENCY_UNIT},
                    {RPCResult::Type::STR_AMOUNT, "asset_amount", "the balance asset amount in satoshis"},
                }
            }
        },	
        RPCExamples{	
            HelpExampleCli("assetallocationbalance", "552723762 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\" 6 9999999")
            + HelpExampleRpc("assetallocationbalance", "552723762, \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\", 6, 9999999")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{	
    uint64_t nAsset = request.params[0].get_uint64();
    UniValue oAsset(UniValue::VOBJ);
    const uint32_t &nBaseAsset = GetBaseAssetID(request.params[0].get_uint64());
    CAsset theAsset;
    if (!GetAsset(nBaseAsset, theAsset))
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to read from asset DB");
    
    int nMinDepth = 1;
    if (!request.params[2].isNull()) {
        nMinDepth = request.params[2].get_int();
    }
    int nMaxDepth = 9999999;
    if (!request.params[3].isNull()) {
        nMaxDepth = request.params[3].get_int();
    }
    // Accept either a bool (true) or a num (>=1) to indicate verbose output.
    bool fVerbose = false;
    if (!request.params[4].isNull()) {
        fVerbose = request.params[4].isNum() ? (request.params[4].get_int() != 0) : request.params[4].get_bool();
    }
    if(fVerbose && !BuildAssetJson(theAsset, nBaseAsset, oAsset))
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to create asset JSON");

    bool include_unsafe = true;
    UniValue paramsFund(UniValue::VARR);
    UniValue includeSafe(UniValue::VBOOL);
    includeSafe.setBool(include_unsafe);
    paramsFund.push_back(nMinDepth);
    paramsFund.push_back(nMaxDepth);
    paramsFund.push_back(request.params[1]);
    paramsFund.push_back(includeSafe);
    
    UniValue options(UniValue::VOBJ);
    options.__pushKV("assetGuid", nAsset);
    paramsFund.push_back(options);
    JSONRPCRequest requestSpent(request.context);
    requestSpent.params = paramsFund;
    requestSpent.URI = request.URI;
    const UniValue &resUTXOs = listunspent().HandleRequest(requestSpent);  
    CAmount nTotalAmount = 0;
    CAmount nAssetTotalAmount = 0;
    const UniValue &resUTXOArr = resUTXOs.get_array();
    if(!resUTXOArr.isNull()) {
        for(size_t i =0;i<resUTXOArr.size();i++) {
            const UniValue &utxoObj = resUTXOArr[i].get_obj();
            nTotalAmount += AmountFromValue(find_value(utxoObj, "amount"));
            const UniValue &assetAmountVal = find_value(utxoObj, "asset_amount");
            if(!assetAmountVal.isNull()) {
                nAssetTotalAmount += AssetAmountFromValue(assetAmountVal, theAsset.nPrecision);
            }
        }
    }
    oAsset.__pushKV("amount", ValueFromAmount(nTotalAmount));
    oAsset.__pushKV("asset_amount", ValueFromAssetAmount(nAssetTotalAmount, theAsset.nPrecision));
    return oAsset;
},
    };
}

static RPCHelpMan sendfrom() {
    return RPCHelpMan{"sendfrom",	
        "\nSend an amount to a given address from a specified address.\n",	
        {	
            {"funding_address", RPCArg::Type::STR, RPCArg::Optional::NO, "The syscoin address to send from"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The syscoin address to send to."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send. eg 0.1"},
            {"minconf", RPCArg::Type::NUM, /* default */ "1", "The minimum confirmations to filter"},
            {"maxconf", RPCArg::Type::NUM, /* default */ "9999999", "The maximum confirmations to filter"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id."
            }},	
        },
        RPCExamples{	
            HelpExampleCli("sendfrom",  "\\\"" + EXAMPLE_ADDRESS[0] + "\\\" \\\"" + EXAMPLE_ADDRESS[1] + "\\\" 0.1")
            + HelpExampleRpc("sendfrom", "\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\", 0.1")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{	
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);
    int nMinDepth = 1;
    if (!request.params[3].isNull()) {
        nMinDepth = request.params[3].get_int();
    }
    int nMaxDepth = 9999999;
    if (!request.params[4].isNull()) {
        nMaxDepth = request.params[4].get_int();
    }
    const std::string& strFromAddress = request.params[0].get_str();
    const CTxDestination &from = DecodeDestination(strFromAddress);
    if (!IsValidDestination(from)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address");
    }
    UniValue paramsFund(UniValue::VARR);
    UniValue paramsAddress(UniValue::VARR);
    paramsAddress.push_back(strFromAddress);
    paramsFund.push_back(nMinDepth);
    paramsFund.push_back(nMaxDepth);
    paramsFund.push_back(paramsAddress);
    JSONRPCRequest requestSpent(request.context);
    requestSpent.params = paramsFund;
    requestSpent.URI = request.URI;
    const UniValue &resUTXOs = listunspent().HandleRequest(requestSpent);
    const UniValue &resUTXOArr = resUTXOs.get_array();
    CCoinControl coin_control;
    if(!resUTXOArr.isNull()) {
        for(size_t i =0;i<resUTXOArr.size();i++) {
            const UniValue& utxoObj = resUTXOArr[i].get_obj();
            const uint256 &txid = ParseHashO(utxoObj, "txid");
            const int &nOut = find_value(utxoObj, "vout").get_int();
            const UniValue& assetObj = find_value(utxoObj, "asset_guid");
            // since we are sending SYS, don't send asset on any UTXO's
            if(assetObj.isNull()) {
                coin_control.Select(COutPoint(txid, nOut));
            }
        }
    }

    const CTxDestination &dest = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid to address");
    }
    // Amount
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if(!coin_control.HasSelected())
        throw JSONRPCError(RPC_TYPE_ERROR, "Could not find inputs to select");
    coin_control.fAllowOtherInputs = false;
    coin_control.destChange = from;
    EnsureWalletIsUnlocked(pwallet);
    mapValue_t mapValue;
    const CRecipient & recipient = {GetScriptForDestination(dest), nAmount, false};
	std::vector<CRecipient> vecSend;
	vecSend.push_back(recipient);
    return SendMoney(pwallet, coin_control, vecSend, mapValue, false); 
},
    };
}
namespace
{

/**
 * Helper class that keeps track of reserved keys that are used for mining
 * coinbases.  We also keep track of the block hash(es) that have been
 * constructed based on the key, so that we can mark it as keep and get a
 * fresh one when one of those blocks is submitted.
 */
class ReservedKeysForMining
{

private:

  /**
   * The per-wallet data that we store.
   */
  struct PerWallet
  {

    /**
     * The current coinbase script.  This has been taken out of the wallet
     * already (and marked as "keep"), but is reused until a block actually
     * using it is submitted successfully.
     */
    CScript coinbaseScript;

    /** All block hashes (in hex) that are based on the current script.  */
    std::set<std::string> blockHashes;

    explicit PerWallet (const CScript& scr)
      : coinbaseScript(scr)
    {}

    PerWallet (PerWallet&&) = default;

  };

  /**
   * Data for each wallet that we have.  This is keyed by CWallet::GetName,
   * which is not perfect; but it will likely work in most cases, and even
   * when two different wallets are loaded with the same name (after each
   * other), the worst that can happen is that we mine to an address from
   * the other wallet.
   */
  std::map<std::string, PerWallet> data;

  /** Lock for this instance.  */
  mutable RecursiveMutex cs;

public:

  ReservedKeysForMining () = default;

  /**
   * Retrieves the key to use for mining at the moment.
   */
  CScript
  GetCoinbaseScript (CWallet* pwallet)
  {
    LOCK2 (cs, pwallet->cs_wallet);

    const auto mit = data.find (pwallet->GetName ());
    if (mit != data.end ())
      return mit->second.coinbaseScript;

    ReserveDestination rdest(pwallet, pwallet->m_default_address_type);
    CTxDestination dest;
    if (!rdest.GetReservedDestination (dest, false))
      throw JSONRPCError (RPC_WALLET_KEYPOOL_RAN_OUT,
                          "Error: Keypool ran out,"
                          " please call keypoolrefill first");
    rdest.KeepDestination ();

    const CScript res = GetScriptForDestination (dest);
    data.emplace (pwallet->GetName (), PerWallet (res));
    return res;
  }

  /**
   * Adds the block hash (given as hex string) of a newly constructed block
   * to the set of blocks for the current key.
   */
  void
  AddBlockHash (const CWallet* pwallet, const std::string& hashHex)
  {
    LOCK (cs);

    const auto mit = data.find (pwallet->GetName ());
    assert (mit != data.end ());
    mit->second.blockHashes.insert (hashHex);
  }

  /**
   * Marks a block as submitted, releasing the key for it (if any).
   */
  void
  MarkBlockSubmitted (const CWallet* pwallet, const std::string& hashHex)
  {
    LOCK (cs);

    const auto mit = data.find (pwallet->GetName ());
    if (mit == data.end ())
      return;

    if (mit->second.blockHashes.count (hashHex) > 0)
      data.erase (mit);
  }

};

ReservedKeysForMining g_mining_keys;

} // anonymous namespace

static RPCHelpMan getauxblock()
{
    return RPCHelpMan{"getauxblock",
                "\nCreates or submits a merge-mined block.\n"
                "\nWithout arguments, creates a new block and returns information\n"
                "required to merge-mine it.  With arguments, submits a solved\n"
                "auxpow for a previously returned block.\n",
                {
                    {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "Hash of the block to submit"},
                    {"auxpow", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "Serialised auxpow found"},
                },
                {
                    RPCResult{"without arguments",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "hash of the created block"},
                            {RPCResult::Type::NUM, "chainid", "chain ID for this block"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", "hash of the previous block"},
                            {RPCResult::Type::NUM, "coinbasevalue", "value of the block's coinbase"},
                            {RPCResult::Type::STR, "bits", "compressed target of the block"},
                            {RPCResult::Type::NUM, "height", "height of the block"},
                            {RPCResult::Type::STR, "_target", "target in reversed byte order, deprecated"},
                        },
                    },
                    RPCResult{"with arguments",
                        RPCResult::Type::BOOL, "xxxxx", "whether the submitted block was correct"
                    },
                },
                RPCExamples{
                    HelpExampleCli("getauxblock", "")
                    + HelpExampleCli("getauxblock", "\"hash\" \"serialised auxpow\"")
                    + HelpExampleRpc("getauxblock", "")
                },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    /* RPCHelpMan::Check is not applicable here since we have the
       custom check for exactly zero or two arguments.  */
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }
    /* Create a new block */
    if (request.params.size() == 0)
    {
        const CScript coinbaseScript = g_mining_keys.GetCoinbaseScript(pwallet);
        const UniValue res = AuxpowMiner::get().createAuxBlock(coinbaseScript, request.context);
        g_mining_keys.AddBlockHash(pwallet, res["hash"].get_str ());
        return res;
    }

    /* Submit a block instead.  */
    CHECK_NONFATAL(request.params.size() == 2);
    const std::string& hash = request.params[0].get_str();

    const bool fAccepted
        = AuxpowMiner::get().submitAuxBlock(hash, request.params[1].get_str(), request.context);
    if (fAccepted)
        g_mining_keys.MarkBlockSubmitted(pwallet, hash);

    return fAccepted;
},
    };
}

Span<const CRPCCommand> GetAssetWalletRPCCommands()
{
// clang-format off
static const CRPCCommand commands[] =
{ 
    //  category              name                                actor (function)      
    //  --------------------- ------------------------          -----------------------

   /* assets using the blockchain, coins/points/service backed tokens*/
    { "syscoinwallet",            &syscoinburntoassetallocation,  }, 
    { "syscoinwallet",            &convertaddresswallet,          },
    { "syscoinwallet",            &assetallocationburn,           }, 
    { "syscoinwallet",            &assetallocationmint,           },     
    { "syscoinwallet",            &assetnew,                      },
    { "syscoinwallet",            &assetnewtest,                  },
    { "syscoinwallet",            &assetupdate,                   },
    { "syscoinwallet",            &assettransfer,                 },
    { "syscoinwallet",            &assetsend,                     },
    { "syscoinwallet",            &assetsendmany,                 },
    { "syscoinwallet",            &assetallocationsend,           },
    { "syscoinwallet",            &assetallocationsendmany,       },
    { "syscoinwallet",            &listunspentasset,              },
    { "syscoinwallet",            &signhash,                      },
    { "syscoinwallet",            &signmessagebech32,             },
    { "syscoinwallet",            &addressbalance,                },
    { "syscoinwallet",            &assetallocationbalance,        },
    { "syscoinwallet",            &sendfrom,                      },

    /** Auxpow wallet functions */
    { "syscoinwallet",            &getauxblock,                   },
};
// clang-format on
    return MakeSpan(commands);
}
