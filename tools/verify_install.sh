#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Post-install sanity check over adb (needs root on the device via su).
set -uo pipefail
su() { adb shell su -c "$*"; }
echo "== module dir";        su 'ls -la /data/adb/modules/pinning_haters 2>&1 | head -20'
echo "== zygisk library";    su 'ls -la /data/adb/modules/pinning_haters/zygisk 2>&1'
echo "== config";            su 'ls -la /data/adb/pinning_haters 2>&1; cat /data/adb/pinning_haters/config.json 2>&1'
echo "== recent logs";       su 'ls -lt /data/adb/pinning_haters/log 2>&1 | head -10'
echo "== zygisk host";       su 'ls /data/adb/modules 2>&1 | grep -iE "zygisk|neozygisk"; magisk --sqlite "select value from settings where key='"'"'zygisk'"'"'" 2>/dev/null'
echo "== abi / api";         adb shell getprop ro.product.cpu.abi; adb shell getprop ro.build.version.sdk
