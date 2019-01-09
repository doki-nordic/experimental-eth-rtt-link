#!/bin/bash
#
# Copyright (c) 2019 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

echo > version.make

while read -r line; do
    if [[ $line =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        echo CFLAGS+=-DAPP_MAJOR_VERSION=${BASH_REMATCH[1]} -DAPP_MINOR_VERSION=${BASH_REMATCH[2]} -DAPP_MICRO_VERSION=${BASH_REMATCH[3]} > version.make
    fi
done <<< `git tag -l --points-at HEAD`
