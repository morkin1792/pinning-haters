#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Repeatable device checks for a rooted test phone reachable over adb. Every subcommand is one of
# the steps docs/testing.md asks for before a release; they were run by hand on the Redmi K20 first.
#
#   PH_DEVICE=192.168.1.253:5555 PH_PIN=909090 tools/device_test.sh <subcommand> [args]
#
#   install <arm64-v8a.so>      push through a NEW inode (never cp over the live file), reboot, unlock
#   unlock                      wake, swipe, type PH_PIN
#   config <file.json>          replace /data/adb/pinning_haters/config.json (hot-reloaded)
#   log <package>               ladder lines of the package's newest module log
#   testapp [proxy host:port]   run tests/test-app's checks, print verdicts (needs the app installed)
#   integrity                   the test app's executable-bytes-vs-disk check
#   demo <button-text>...       HTTP Toolkit pinning demo: tap buttons by their text, read the colour
#   dnat <package> <ip:port> on|off   redirect the package's TCP 443 (Flutter ignores the proxy setting)
#   maps <package>              our module's and the host's mappings in the running process
set -euo pipefail
dev=${PH_DEVICE:?set PH_DEVICE to the adb serial}
pin=${PH_PIN:-}
adb() { command adb -s "$dev" "$@"; }
su() { adb shell "su -c '$*'"; }
demo=tech.httptoolkit.pinning_demo
testapp=dev.pinninghaters.testapp

unlock() {
    adb shell "svc power stayon true; input keyevent KEYCODE_WAKEUP; sleep 1; input keyevent 82; sleep 1; ${pin:+input text $pin; input keyevent 66;} sleep 2"
    adb shell "dumpsys window | grep -oE 'isKeyguardShowing=(true|false)' | head -1"
}

wait_boot() {
    sleep 25
    for _ in $(seq 1 50); do
        command adb connect "$dev" >/dev/null 2>&1 || true
        up=$(adb shell cat /proc/uptime 2>/dev/null | cut -d. -f1 || true)
        if [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && [ -n "$up" ] && [ "$up" -lt 600 ]; then
            echo "booted (uptime ${up}s)"; sleep 5; return
        fi
        sleep 5
    done
    echo "device did not come back" >&2; exit 1
}

# Bounds of the first UI node whose text matches; prints "x y" of its centre.
node_center() {
    adb shell "uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; cat /sdcard/ui.xml" | python3 -c "
import re, sys
x = sys.stdin.read()
m = re.search(r'text=\"' + re.escape(sys.argv[1]) + r'\"[^>]*bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"', x)
print((int(m.group(1)) + int(m.group(3))) // 2, (int(m.group(2)) + int(m.group(4))) // 2) if m else print('')" "$1"
}

pixel_verdict() {  # $1 png, $2 x, $3 y
    python3 -c "
from PIL import Image
p = Image.open('$1').convert('RGB').getpixel(($2, $3))
print({(0, 145, 17): 'GREEN', (98, 0, 238): 'PURPLE (no verdict)'}.get(p, 'RED' if p[0] > 120 and p[1] < 80 else str(p)))"
}

case "${1:-}" in
install)
    so=${2:?path to arm64-v8a.so}
    adb push "$so" /data/local/tmp/ph.so >/dev/null
    su "cp /data/local/tmp/ph.so /data/adb/modules/pinning_haters/zygisk/arm64-v8a.so.new && chmod 644 /data/adb/modules/pinning_haters/zygisk/arm64-v8a.so.new && mv /data/adb/modules/pinning_haters/zygisk/arm64-v8a.so.new /data/adb/modules/pinning_haters/zygisk/arm64-v8a.so && sha256sum /data/adb/modules/pinning_haters/zygisk/arm64-v8a.so | cut -c1-16"
    sha256sum "$so" | cut -c1-16
    su "sleep 1; reboot" || true
    wait_boot
    unlock
    ;;
unlock) unlock ;;
config)
    adb push "${2:?config json}" /data/local/tmp/ph-config.json >/dev/null
    su "cp /data/local/tmp/ph-config.json /data/adb/pinning_haters/config.json; chmod 600 /data/adb/pinning_haters/config.json; cat /data/adb/pinning_haters/config.json"; echo
    ;;
log)
    pkg=${2:?package}
    su "f=\$(ls -t /data/adb/pinning_haters/log/$pkg-*.log 2>/dev/null | head -1); [ -n \"\$f\" ] && grep -E \"\\[init\\]|\\[coverage\\]|\\[hide\\]|overridden|WARN|ERROR\" \$f | cut -c1-160 || echo no-log"
    ;;
testapp|integrity)
    proxy=${2:-}
    previous=$(adb shell settings get global http_proxy | tr -d '\r')
    [ -n "$proxy" ] && adb shell "settings put global http_proxy $proxy"
    button=$([ "$1" = testapp ] && echo "Run pinning checks" || echo "Check executable bytes vs disk")
    adb shell "logcat -c 2>/dev/null; am force-stop $testapp; sleep 1; monkey -p $testapp -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1; sleep 6"
    read -r x y < <(node_center "$button")
    [ -n "$x" ] || { echo "button '$button' not on screen" >&2; exit 1; }
    adb shell "input tap $x $y; sleep $([ "$1" = testapp ] && echo 45 || echo 25); logcat -d -s pinning-haters-test:* | grep -E 'PASS|FAIL' | sed -E 's/^.*pinning-haters-test[^:]*: //' | cut -c1-140 | sort -u"
    # Put back whatever was set before ("null" means none).
    if [ -n "$proxy" ]; then
        # `settings delete` leaves ConnectivityService on the old proxy; ":0" is what clears it.
        if [ "$previous" = null ] || [ -z "$previous" ]; then adb shell "settings put global http_proxy :0" >/dev/null
        else adb shell "settings put global http_proxy $previous" >/dev/null; fi
    fi
    ;;
demo)
    shift
    adb shell "am force-stop $demo; sleep 1; monkey -p $demo -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1; sleep 7"
    for text in "$@"; do
        read -r x y < <(node_center "$text")
        [ -n "$x" ] || { echo "$text: not found"; continue; }
        adb shell "input tap $x $y; sleep 8"
        adb exec-out screencap -p > /tmp/ph-demo.png
        echo "$text: $(pixel_verdict /tmp/ph-demo.png 60 "$y")"
    done
    ;;
dnat)
    pkg=${2:?package}; dst=${3:?ip:port}; state=${4:?on|off}
    uid=$(adb shell "dumpsys package $pkg | grep -m1 userId=" | sed -E 's/.*userId=([0-9]+).*/\1/' | tr -d '\r')
    op=$([ "$state" = on ] && echo -I || echo -D)
    su "iptables -t nat $op OUTPUT -p tcp --dport 443 -m owner --uid-owner $uid -j DNAT --to-destination $dst; ip6tables $op OUTPUT -p tcp --dport 443 -m owner --uid-owner $uid -j REJECT; iptables -t nat -S OUTPUT | grep -c uid-owner || true"
    ;;
maps)
    pkg=${2:?package}
    su "pid=\$(pidof $pkg | cut -d\" \" -f1); [ -n \"\$pid\" ] && grep -E 'pinning_haters|zygisk' /proc/\$pid/maps | awk '{print \$2, \$6}' | sort | uniq -c || echo not-running"
    ;;
*) sed -n 2,20p "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
