#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test external signer.

Verify that a bitcoind node can use an external signer command
"""
import os
import platform

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class SignerTest(BitcoinTestFramework):
    def mock_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks', 'signer.py')
        if platform.system() == "Windows":
            return "py " + path
        else:
            return path

    def set_test_params(self):
        self.num_nodes = 3

        self.extra_args = [
            [],
            ['-signer=%s' % self.mock_signer_path()],
            ['-signer=%s' % "fake.py"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_external_signer()

    def set_mock_result(self, node, res):
        f = open(os.path.join(node.cwd, "mock_result"), "w", encoding="utf8")
        f.write(res)
        f.close()

    def clear_mock_result(self, node):
        os.remove(os.path.join(node.cwd, "mock_result"))

    def run_test(self):
        self.log.info('-signer=%s' % self.mock_signer_path())
        assert_equal(self.nodes[0].getbalance(), 1250)

if __name__ == '__main__':
    SignerTest().main()
