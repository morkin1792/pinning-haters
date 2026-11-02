#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Release criterion "no crashes in 24 hours" (plan §1.16 item 9), automated part: every INTERVAL
# seconds, launch each targeted package, let it run, and record whether it is still alive, any new
# crash-buffer entries for it, new tombstones, and whether the module's companion was restarted.
# Normal use of the phone in between is the other half; this only guarantees the targets run.
#
#   PH_DEVICE=<serial> tools/stability_run.sh <hours> <interval-seconds> <package>... > run.log
#
# Prints one line per launch and a summary at the end. Needs the phone on adb and kept awake
# (`svc power stayon true`); it does not change the module config.
set -uo pipefail
hours=${1:?hours}; interval=${2:?interval seconds}; shift 2
[ $# -gt 0 ] || { echo "name at least one targeted package" >&2; exit 1; }
adb() { command adb ${PH_DEVICE:+-s "$PH_DEVICE"} "$@"; }
su() { adb shell "su -c '$*'" | tr -d '\r'; }

# Zygisk Next names it "zn-zygisk-companion64 pinning_haters"; other hosts use similar names.
companion_pid() { adb shell "ps -A -o PID,ARGS" | tr -d '\r' | awk '/companion/ && /pinning_haters/ {print $1; exit}'; }
tombstones() { su "ls /data/tombstones 2>/dev/null | grep -c tombstone"; }

end=$(( $(date +%s) + hours * 3600 ))
start_tomb=$(tombstones); start_comp=$(companion_pid)
launches=0; dead=0; crashes=0
echo "start $(date -Is) tombstones=$start_tomb companion=$start_comp packages=$*"
adb logcat -b crash -c
while [ "$(date +%s)" -lt "$end" ]; do
    adb shell "svc power stayon true; input keyevent KEYCODE_WAKEUP" >/dev/null 2>&1
    for pkg in "$@"; do
        adb shell "am force-stop $pkg; monkey -p $pkg -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
        sleep 25
        pid=$(adb shell pidof "$pkg" | tr -d '\r')
        crash=$(adb logcat -b crash -d | grep -c "$pkg")
        launches=$((launches + 1))
        [ -z "$pid" ] && dead=$((dead + 1))
        [ "$crash" -gt 0 ] && crashes=$((crashes + 1)) && adb logcat -b crash -d | grep -A12 "$pkg" | head -30
        adb logcat -b crash -c
        echo "$(date -Is) $pkg alive=$([ -n "$pid" ] && echo yes || echo NO) crash_lines=$crash tombstones=$(tombstones) companion=$(companion_pid)"
        adb shell "am force-stop $pkg" >/dev/null 2>&1
    done
    sleep "$interval"
done
echo "end $(date -Is) launches=$launches not_alive=$dead with_crash=$crashes tombstones=$start_tomb->$(tombstones) companion=$start_comp->$(companion_pid)"
