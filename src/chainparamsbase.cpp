// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"

#include "tinyformat.h"
#include "util.h"

#include <assert.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::REGTEST = "regtest";
const std::string CBaseChainParams::BSAFENET = "bsafenet";
const std::string CBaseChainParams::BSAFENETLT1 = "bsafenetlt1";
const std::string CBaseChainParams::BSAFENETLT2 = "bsafenetlt2";
const std::string CBaseChainParams::BSAFENETLT3 = "bsafenetlt3";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
        strUsage += HelpMessageOpt("-bsafenet", "Enter segregated witness test mode on bsafenet. ");
    }
}

/**
 * Main network
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 8332;
    }
};
static CBaseMainParams mainParams;

/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CBaseChainParams
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 18332;
        strDataDir = "testnet3";
    }
};
static CBaseTestNetParams testNetParams;

/**
 * bsafenet
 */
class CBaseSafeNetParams : public CBaseChainParams
{
public:
    CBaseSafeNetParams()
    {
        nRPCPort = 34822;
        strDataDir = "bsafenet";
    }
};
static CBaseSafeNetParams bSafeParams;

class CBaseSafeNetLT1Params : public CBaseChainParams
{
public:
    CBaseSafeNetLT1Params()
    {
        nRPCPort = 34822 + 100;
        strDataDir = "bsafenetlt1";
    }
};
static CBaseSafeNetLT1Params bSafelt1Params;

class CBaseSafeNetLT2Params : public CBaseChainParams
{
public:
    CBaseSafeNetLT2Params()
    {
        nRPCPort = 34822 + 200;
        strDataDir = "bsafenetlt2";
    }
};
static CBaseSafeNetLT2Params bSafelt2Params;

class CBaseSafeNetLT3Params : public CBaseChainParams
{
public:
    CBaseSafeNetLT3Params()
    {
        nRPCPort = 34822 + 300;
        strDataDir = "bsafenetlt3";
    }
};
static CBaseSafeNetLT3Params bSafelt3Params;

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseChainParams
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 18332;
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams;

static CBaseChainParams* pCurrentBaseParams = 0;

const CBaseChainParams& BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

CBaseChainParams& BaseParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else if (chain == CBaseChainParams::BSAFENET)
        return bSafeParams;
    else if (chain == CBaseChainParams::BSAFENETLT1)
            return bSafelt1Params;
    else if (chain == CBaseChainParams::BSAFENETLT2)
            return bSafelt2Params;
    else if (chain == CBaseChainParams::BSAFENETLT3)
            return bSafelt3Params;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    pCurrentBaseParams = &BaseParams(chain);
}

std::string ChainNameFromCommandLine()
{
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    bool fbsafeNet = GetBoolArg("-bsafenet", false);
    bool fbsafenetlt1 = GetBoolArg("-bsafenetlt1", false);
    bool fbsafenetlt2 = GetBoolArg("-bsafenetlt2", false);
    bool fbsafenetlt3 = GetBoolArg("-bsafenetlt3", false);
    
    if ((int)fRegTest + (int)fTestNet + (int)fbsafeNet  + (int)fbsafenetlt1 + (int)fbsafenetlt2 + (int)fbsafenetlt3> 1)
        throw std::runtime_error("Invalid combination of -regtest, -testnet, -bsafenet.");
    if (fRegTest)
        return CBaseChainParams::REGTEST;
    if (fTestNet)
        return CBaseChainParams::TESTNET;
    if (fbsafeNet)
        return CBaseChainParams::BSAFENET;
    if (fbsafenetlt1)
        return CBaseChainParams::BSAFENETLT1;
    if (fbsafenetlt2)
        return CBaseChainParams::BSAFENETLT2;
    if (fbsafenetlt3)
        return CBaseChainParams::BSAFENETLT3;
    return CBaseChainParams::MAIN;
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
