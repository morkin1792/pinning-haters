#!/system/bin/sh
# Module installer hook (Magisk, KernelSU, APatch). util_functions.sh is already loaded.
SKIPUNZIP=0

[ "$ARCH" = "arm64" ] || abort "! pinning-haters is arm64-only (device ABI: $ARCH)"
[ "$API" -ge 30 ] || abort "! Android 11 (API 30) or newer is required (device API: $API)"

CFG_DIR=/data/adb/pinning_haters
ui_print "- Zygisk module, opt-in per package. Zygisk must be enabled:"
ui_print "  Magisk: Settings > Zygisk. KernelSU/APatch: install ZygiskNext or NeoZygisk."

mkdir -p "$CFG_DIR/log"
if [ ! -f "$CFG_DIR/config.json" ]; then
    cp "$MODPATH/config.default.json" "$CFG_DIR/config.json"
    ui_print "- Wrote $CFG_DIR/config.json (no packages targeted yet)"
fi
chown -R 0:0 "$CFG_DIR"
chmod 700 "$CFG_DIR" "$CFG_DIR/log"
chmod 600 "$CFG_DIR/config.json"
rm -f "$MODPATH/config.default.json"

ui_print "- Nothing happens until you add a package."
ui_print "  KernelSU/APatch: open the module's WebUI. Magisk: edit $CFG_DIR/config.json as root."
