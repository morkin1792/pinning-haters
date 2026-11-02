#!/system/bin/sh
# late_start service: re-assert root-only permissions on the config directory every boot.
d=/data/adb/pinning_haters
mkdir -p "$d/log"
chown -R 0:0 "$d"
chmod 700 "$d" "$d/log"
[ -f "$d/config.json" ] && chmod 600 "$d/config.json"
exit 0
