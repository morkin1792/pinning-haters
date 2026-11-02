#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Pulls the libraries our ELF contracts depend on into tools/reference-libs/<api>/ for each API level
# given, from Google's arm64 AVD system images (google_apis). No root and no loop mounts: the ext4
# partitions are read with debugfs straight out of the image. Needs curl, python3, debugfs.
#
#   tools/pull_reference_libs.sh 30 31 33 34 35 36
#   KEEP_DOWNLOADS=1 ... keeps the multi-GB zip and system.img under tools/reference-libs/.download
#
# Factory images (developers.google.com/android/images) remain the authoritative source; AVD images
# are built from the same tree and carry the same APEXes, which is all the contracts look at.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root="$here/reference-libs"
dl="$root/.download"
manifest_url="https://dl.google.com/android/repository/sys-img/google_apis/sys-img2-3.xml"
base_url="https://dl.google.com/android/repository/sys-img/google_apis/"

for tool in curl python3 debugfs; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[ $# -gt 0 ] || { echo "usage: $0 <api-level>..." >&2; exit 2; }
mkdir -p "$dl"

curl -fsSL --retry 3 -o "$dl/sys-img2-3.xml" "$manifest_url"

for api in "$@"; do
    dest="$root/$api"
    file=$(python3 - "$dl/sys-img2-3.xml" "$api" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot(); want = sys.argv[2]
best = None
for p in root.iter():
    if not p.tag.endswith("remotePackage"): continue
    path = p.get("path", "").lower()
    # plain google_apis arm64 images only: no 16 KiB-page variants, no SDK-extension, beta or canary trains
    if "arm64-v8a" not in path or "google_apis;" not in path or "ps16k" in path: continue
    if "-ext" in path or "beta" in path or "canary" in path: continue
    api = p.find(".//api-level")
    if api is None or api.text != want: continue
    rev = int(p.find(".//revision/major").text)
    url = next(u.text for u in p.iter("url"))
    if best is None or rev > best[0]: best = (rev, url)
print(best[1] if best else "")
PY
)
    [ -n "$file" ] || { echo "API $api: no arm64 google_apis image in the manifest" >&2; exit 1; }
    zip="$dl/$file"
    img="$dl/system-$api.img"
    echo "== API $api: $file"
    if [ ! -s "$zip" ]; then
        curl -fsSL --retry 3 -C - -o "$zip.part" "$base_url$file"
        mv "$zip.part" "$zip"
    fi
    python3 - "$zip" "$img" <<'PY'
import sys, zipfile, shutil
z = zipfile.ZipFile(sys.argv[1])
member = next(n for n in z.namelist() if n.endswith("/system.img") or n == "system.img")
with z.open(member) as src, open(sys.argv[2], "wb") as dst:
    shutil.copyfileobj(src, dst, 1 << 24)
PY
    mkdir -p "$dest"
    python3 "$here/extract_apex_libs.py" "$img" "$dest"
    ls -la "$dest"
    [ "${KEEP_DOWNLOADS:-0}" = 1 ] || rm -f "$zip" "$img"
done
