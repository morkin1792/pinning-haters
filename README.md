# pinning-haters

A Zygisk module that bypasses TLS certificate pinning in Android apps you are authorised to test.
Install it once, name the packages you want to inspect, point them at your interception proxy.
No Frida, no recompiled APKs, no Xposed framework, no manager app.

What sets it apart from other Zygisk unpinning modules: **by default it modifies zero bytes of
executable code in the target process.** It rewrites pointers in data pages, patches the app's own
DEX while ART verifies it, and does file work from a root companion outside the process. A
memory-versus-disk check of any library's code finds nothing. Why that matters and how it is done:
[docs/detection-model.md](docs/detection-model.md), [docs/reference.md](docs/reference.md).

## Status

**Pre-release v0.1.0 (2026-11-04).** Verified on two devices: Android 11 (APatch + Zygisk Next) and
Android 16 (KernelSU + Zygisk Next). Android 12 to 15 and Magisk as a host are untested.

What works on both devices: platform trust and Network Security Config pins, custom
`TrustManager`s, TrustKit, OkHttp `CertificatePinner`, Flutter and other statically linked
BoringSSL/OpenSSL, WebView, a React Native app carrying a protection SDK. The module survives
`bg-dexopt` and hides its own mapping. The full record is in
[docs/android-versions.md](docs/android-versions.md); what is out of reach is in
[docs/known-limitations.md](docs/known-limitations.md).

TLS only. Root and tamper hiding lives in
[rootcheck-haters](https://github.com/morkin1792/rootcheck-haters); install both when an app checks
for root.

## Requirements

- Android 11 to 16 (API 30 to 36), arm64-v8a.
- Root with a Zygisk implementation (KernelSU + Zygisk Next, APatch, Magisk 26+). KernelSU and
  APatch get a WebUI; Magisk users edit a JSON file.

## Install

1. Download `pinning-haters-<version>.zip` from the Releases page, or build it with
   `tools/package.sh` (see [docs/reference.md](docs/reference.md#building)).
2. Flash it from your root manager's module screen and reboot.

The module is **inert until you add a package**. It never touches `system_server` and has no
"all apps" mode.

## Target a package

**KernelSU / APatch:** open the module's WebUI in the manager, pick the package, turn logging on.

**Magisk:** write `/data/adb/pinning_haters/config.json` as root:

```json
{
  "version": 2,
  "packages": { "com.example.app": {} },
  "log": { "enabled": true }
}
```

Then force-stop the app and start it again. No reboot: the companion re-reads the config at every
launch. No proxy CA is needed for targeted packages.

## Check that it worked

```sh
adb shell su -c 'ls -t /data/adb/pinning_haters/log | head -1'
adb shell su -c 'cat /data/adb/pinning_haters/log/<file>' | grep coverage
```

`present=yes reachable=yes` means the surface was hooked. `present=yes reachable=no` names the
reason and, when a higher tier would help, the tier to set for that one package. `present=no` is
normal. Every key, every reason: [docs/reference.md](docs/reference.md),
[docs/coverage.md](docs/coverage.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/reference.md](docs/reference.md) | How it works, hosts, every config key, log format, build and test commands. |
| [docs/coverage.md](docs/coverage.md) | The coverage log: every surface, every reason, what to change. |
| [docs/stealth-tiers.md](docs/stealth-tiers.md) | `max` / `balanced` / `compat` and the per-package override. |
| [docs/known-limitations.md](docs/known-limitations.md) | What is not and will not be reached. |
| [docs/testing.md](docs/testing.md) | Host tests, the manual matrix, the release check. |
| [docs/architecture.md](docs/architecture.md) | Components, wire protocol, the GOT edges, the DEX path. |
| [docs/detection-model.md](docs/detection-model.md) | The primitive ranking that decides every hook. |
| [docs/threat-model.md](docs/threat-model.md) | Who this is for and what detects it. |
| [docs/android-versions.md](docs/android-versions.md) | Verification record per API level and device. |
| [docs/adding-hooks.md](docs/adding-hooks.md) | Hooks are data: adding a target. |
| [AGENTS.md](AGENTS.md) | Decision log for contributors. |
| [CHANGELOG.md](CHANGELOG.md), [DISCLAIMER.md](DISCLAIMER.md) | Release history, terms of use. |

## License

GPL-3.0-or-later. See `LICENSE`. The vendored `nlohmann/json` header (`module/jni/config/json.hpp`)
is MIT.
