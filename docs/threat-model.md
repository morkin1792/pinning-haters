# Threat model

Who pinning-haters is for, what it assumes, what can notice it, and what it will never defend
against. Read this before relying on the module for anything where being noticed matters.

## Who it is for

Mobile security researchers, penetration testers and bug hunters inspecting the traffic of Android
apps they are authorised to test, on Zygisk-rooted devices they control. The user is assumed to know
what Zygisk is, how to install a module, and what certificate pinning is.

## Who it is not for

- **Not a malware-development tool.** Features that only make sense for malicious use (covert
  payload injection, persistence beyond the module's needs, exfiltration, any network traffic) are
  refused.
- **Not for developers debugging their own app.** Use `network_security_config.xml` debug overrides;
  they are the supported mechanism and modify nothing at runtime.
- **Not a replacement for installing your proxy CA.** Targeted packages need no CA. For broad
  interception, a system-CA module is quieter than targeting every package here.
- **Not for actively defended apps, and not a root hider.** RASP products (Promon SHIELD, Talsec,
  Appdome, Build38, V-Key, DexProtector) are not engaged; root and tamper hiding moved to a separate
  module. This one targets apps without serious anti-tamper.

## Assumptions

- The device is rooted and the user has root. The companion runs as root inside the Zygisk daemon.
- The host (Magisk, KernelSU + ZygiskNext, KernelSU-Next + NeoZygisk, APatch) is trusted. It
  already runs code in every app process; we add nothing to that trust boundary.
- The target app is, at worst, a Phase 1 app: it may do ordinary checks (is my `TrustManager`
  called, does the connection fail with a wrong pin) but does not deploy a RASP SDK.
- `/data/adb/pinning_haters/` is readable only by root. Config and logs never leave it, and the
  target process never touches it.

## What the module exposes at `max`, and what notices it

`max` is quiet, not invisible. Each item below is something a deliberately hunting app could check.
None of them is a routine check in non-RASP apps today; all of them are cheap once an app decides to
look.

| Exposure | How it would be noticed | Notes |
|---|---|---|
| Rewritten GOT slots in `libdexfile.so`, `libjavacrypto.so`, `libnativeloader.so`, `libart.so`, `libartbase.so` | Snapshot the GOT at load and re-read it; or check that each slot points inside the expected provider library (`libz.so`, the conscrypt `libssl.so`, `libdl.so`, `libc.so`). Ours point into our `.so`. | Primitive 3 on the ranking. Rare in the wild. |
| Rewritten GOT slots in app-private libraries (only when the app bundles TLS) | Same, and app libraries are the first thing a scanner walks. | Primitive 4. Used only where no system-library edge exists. |
| Modified `insns[]` in the app's in-memory DEX | Compare the in-memory DEX with the APK's DEX (hash the mapped DEX, or re-read the APK entry and diff). The header checksum still matches the APK; the instruction bytes of patched methods do not. | Primitive 1. Effectively never seen. |
| Absent oat artifacts | `stat` the package's `base.odex`/`base.vdex`; notice the app is running interpreted/JIT when it should have AOT code; notice startup time. | Primitive 2. The one side effect of companion-side work that is visible from inside the process. |
| An extra pipe descriptor (only with `log.enabled`) | Enumerate `/proc/self/fd`; find a pipe the app did not open. | Off by default. With logging off no descriptor of ours survives `preAppSpecialize`. |
| Our `.so` mapped in the process | Walk `/proc/self/maps` for the path, or look for anonymous executable regions. | The path is gone: the module re-maps its own pages anonymously after hooking (`hide.self_remap`). Four anonymous regions (one executable) remain, and a `dl_iterate_phdr` walk still names us on hosts that load modules through bionic (not Zygisk Next, which uses its own linker). |
| The `TrustManager` threw, but the connection succeeded anyway | A `TrustManager` that records its own rejection and later checks that the socket was torn down would notice the contradiction. | Consequence of wrapping rather than replacing. Replacing would remove this signal and add a louder one ("my `TrustManager` was never called"). |
| Module library path in `/proc/self/maps` (host-dependent) | Walk maps for paths under `/data/adb/modules`. On the Redmi K20 with Zygisk Next 1.4.5 a generic detector app reported `Found Injection` only while the module targeted it; untargeted, the same device showed every other environment finding (Magisk, LSPosed, mounts) but not that one. | Hiding the host's own library is the host's job (see the host tier table); Zygisk Next 1.4.5 did not hide it here. Phase 2 may add self-remapping. |
| Redirected traffic (only for a package with `redirect` set) | Nothing in-process: no hook, and `getpeername` returns the real server. Behavioural probes work: a TCP connection to an address that cannot exist succeeds, HTTP/3 never connects, IPv6 443 is refused, and the peer's certificate is the proxy's. | Primitive 2 (root-side, outside the process). Off by default. Quieter than the system proxy setting or a VPN, both of which an app reads through ordinary APIs. |
| Hooked `__loader_dlopen` / `__loader_android_dlopen_ext` (two `libdl.so` slots) returning normally | Nothing in-process; the slot rewrite above is the only trace. A protection SDK that verifies its *own* `.got.plt` finds nothing: no app-private slot is written for this edge. | |

What is **not** exposed at `max`: no modified executable bytes in any library, so text-segment
CRC checks (the most common anti-hook check outside RASP, and the one that catches every inline
hooking framework) find nothing; no additional threads; no RWX pages; no new mappings beyond our
`.so`; no files opened by us; no logcat lines; no properties set; nothing on `/sdcard`.

## What raising the tier would expose (when those tiers ship)

- `balanced`: text CRC mismatches in each inline-hooked library, unless CRC countermeasures are in
  place. The countermeasures are mandatory for that tier and are Phase 2.1 work.
- `compat`: the standard Xposed entry-point check (ArtMethod entry points outside the `.oat`
  mapping), plus libc CRC mismatches.

## Boundaries the module will not cross

- **TEE / StrongBox-attested chains**: cannot be bypassed from the REE. Permanent.
- **RASP that issues raw syscalls**: a Zygisk module cannot intercept an `openat` performed via
  `svc`. Reaching that needs a kernel-module companion and is a documented boundary.
- **Processes not in `packages`**, including `system_server`: never touched. There is no denylist
  mode because it would mean hooks in every process.
- **Network**: the module never makes a request. `update.json` is fetched only by the host module
  manager when it checks for updates, and only to display a notice. The optional `redirect` key
  changes where a targeted app's own port-443 traffic goes (to the address the user wrote) and
  nothing else.

## Privacy posture

- Configuration lists the packages you are testing. It lives in a root-only path, is never mirrored
  to `/sdcard`, and is read only by the companion. An app with storage permission cannot learn
  whether it is on the list.
- Logs are root-only, off by default, contain the Android version, resolved contracts, tier and
  coverage lines, and nothing from the app's traffic. They rotate after 7 days or 100 MB.
- No telemetry, no analytics, no remote endpoint. "Telemetry" and "logging" are the same local file.

## Residual risk for the user

While a package is targeted, that app accepts any certificate chain from any server, not only your
proxy's. Treat a targeted app as compromised for the duration of the test, and remove it from
`packages` afterwards. See `DISCLAIMER.md`.
