#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# On-device variant of tools/stability_run.sh: runs as root on the phone itself, so the phone can be
# unplugged for the whole run. Holds a wakelock (CPU only, the screen may go off) so the intervals
# are real time and not suspended time; releases it at the end.
#
#   adb push tools/stability_ondevice.sh /data/local/tmp/
#   adb shell "su -c 'setsid nohup sh /data/local/tmp/stability_ondevice.sh 24 1800 <pkg>... >/dev/null 2>&1 &'"
#   later: adb shell su -c cat /data/local/tmp/ph-stability.log
#
# dev.pinninghaters.testapp is started with `--ez run true`, so every round also runs its checks;
# its verdicts are read back from files/last_run.txt (6 PASS lines when everything holds:
# custom_trustmanager, nsc_pins, okhttp_pinner, untrusted_chain, static_openssl, webview). Other
# packages are only launched.
# Unlock the phone once after a reboot before starting: until then credential-encrypted storage is
# locked and no ordinary app can start. Screen off afterwards is fine.
hours=$1; interval=$2; shift 2
log=/data/local/tmp/ph-stability.log
# First argument is hours, or minutes with an "m" suffix (20m): the failure modes this run looks for
# scale with launches, not wall time, so a short interval over 20 minutes exercises the same paths.
case "$hours" in *m) secs=$(( ${hours%m} * 60 ));; *) secs=$(( hours * 3600 ));; esac
end=$(( $(date +%s) + secs ))
tomb() { ls /data/tombstones 2>/dev/null | grep -c '^tombstone_[0-9]*$'; }
comp() { ps -A -o PID,ARGS | awk '/companion/ && /pinning_haters/ {print $1; exit}'; }
echo ph_stability > /sys/power/wake_lock 2>/dev/null
# Doze cuts an app's network while the screen is off, which would turn every check into a
# connection error; the test app is exempted for the run (and only it).
cmd deviceidle whitelist +dev.pinninghaters.testapp >/dev/null 2>&1
echo "start $(date '+%F %T') hours=$hours interval=$interval tombstones=$(tomb) companion=$(comp) packages=$*" >> $log
logcat -b crash -c
launches=0; dead=0; crashed=0
while [ "$(date +%s)" -lt "$end" ]; do
    for p in "$@"; do
        am force-stop "$p"
        if [ "$p" = dev.pinninghaters.testapp ]; then
            am start -n "$p/.MainActivity" --ez run true >/dev/null 2>&1
            sleep 60
        else
            monkey -p "$p" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
            sleep 25
        fi
        pid=$(pidof "$p")
        c=$(logcat -b crash -d | grep -c "$p")
        launches=$((launches + 1))
        [ -z "$pid" ] && dead=$((dead + 1))
        if [ "$c" -gt 0 ]; then
            crashed=$((crashed + 1))
            logcat -b crash -d | grep -A12 "$p" | head -30 >> $log
        fi
        extra=""
        f=/data/data/$p/files/last_run.txt
        if [ "$p" = dev.pinninghaters.testapp ] && [ -f "$f" ]; then
            # A FAIL that is a network error says nothing about the module; count it apart.
            net='ConnectException|UnknownHost|ERR_NAME_NOT_RESOLVED|ERR_INTERNET|tcp connect|timeout'
            extra=" pass=$(grep -c PASS "$f")/6 fail=$(grep FAIL "$f" | grep -v 'expected at max' | grep -cvE "$net") net_errors=$(grep FAIL "$f" | grep -cE "$net") age=$(( $(date +%s) - $(head -1 "$f") ))s"
            grep FAIL "$f" | grep -v 'expected at max' | grep -vE "$net" | cut -c1-160 >> $log
        fi
        echo "$(date '+%F %T') $p alive=$([ -n "$pid" ] && echo yes || echo NO) crash_lines=$c tombstones=$(tomb) companion=$(comp)$extra" >> $log
        logcat -b crash -c
        am force-stop "$p"
    done
    sleep "$interval"
done
echo "end $(date '+%F %T') launches=$launches not_alive=$dead with_crash=$crashed tombstones=$(tomb) companion=$(comp)" >> $log
echo ph_stability > /sys/power/wake_unlock 2>/dev/null
cmd deviceidle whitelist -dev.pinninghaters.testapp >/dev/null 2>&1
