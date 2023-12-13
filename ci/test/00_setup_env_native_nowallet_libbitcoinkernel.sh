#!/usr/bin/env bash
#
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_nowallet_libbitcoinkernel
export CI_IMAGE_NAME_TAG="docker.io/ubuntu:22.04"
# Use minimum supported python3.9 (or best-effort 3.10) and clang-15 with libstdc++-11, see doc/dependencies.md
export PACKAGES="python3-zmq clang-15 llvm-15"
export DEP_OPTS="NO_WALLET=1 CC=clang-15 CXX='clang++-15 -stdlib=libstdc++'"
export GOAL="install"
export BITCOIN_CONFIG="--enable-reduce-exports --enable-experimental-util-chainstate --with-experimental-kernel-lib --enable-shared"
