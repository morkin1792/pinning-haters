# AGENTS.md

This file is for future sessions working on `pinning-haters`. Read it before making architectural
changes. `pinning-haters-plan.md` covers *what* to build; this file covers *why* the decisions were
made and *which decisions should not be casually revisited*.

If you find yourself thinking "wouldn't it be better to just use LSPosed?", "why not filter
`/proc/self/maps`?", or "why is the Java hook list so short?" — the answer is in this file. Read
first, propose changes second.

**Revision note (2026-10-24).** This file was substantially revised together with the v2 plan.
Entries marked **SUPERSEDED** record decisions that were reversed, with the reason. Per the
file's own convention, superseded entries are kept rather than deleted — the reversal reasoning is
usually more useful than the conclusion.

---

## Mission

`pinning-haters` is a Zygisk module that bypasses TLS certificate pinning on Android apps. It is the
spiritual analogue to iOS's `ssl-kill-switch3`, adapted for Android's fundamentally different
pinning architecture.

Audience: mobile security researchers, pentesters and bug hunters on Zygisk-rooted devices. The user
is assumed to know what Zygisk is, how to install a module, and what certificate pinning means.

### The priority order that settles every argument

1. **Low detectability.** Equal-coverage designs are decided by which one modifies less of the
   target process, in the places least likely to be checked.
2. **Coverage.**
3. **Maintainability.**
4. **Convenience.** Never traded against (1).

Coverage that cannot be had quietly is exposed as an **opt-in stealth tier**, per package, never as a
default. If you are about to make the default louder in exchange for reaching one more surface: no.
Add it to `balanced` or `compat` instead and let the coverage ladder tell the user it is there.

### Value proposition versus alternatives

- **vs. Frida**: no frida-server process, no ptrace attachment, no per-session scripts. Survives
  reboots, attaches automatically to allowlisted packages.
- **vs. LSPosed + JustTrustMe**: no framework presence, no `system_server` hooks, no manager APK.
- **vs. apk-mitm**: no recompilation, no signature breakage, works on apps you cannot rebuild.
- **vs. existing Zygisk unpinning modules**: in the default configuration we modify **zero bytes of
  executable code** in the target process. That is the differentiator, and it is a property we check
  mechanically in CI and at release (plan §1.16 item 6), not a claim.

---

## The detection model (read this before proposing any hook)

Every mechanical decision in the project follows from one ranking of hooking primitives, ordered by
how likely a real app is to notice them. Full table in plan §1.1. Condensed:

```
1  DEX bytecode patched in memory before verification   effectively never detected
2  Companion-side file operations, outside the process  nothing in-process to detect
3  GOT slot rewrite in a system library                 rare
4  GOT slot rewrite in an app-private library           uncommon
5  Inline .text patch in a system library               uncommon  (CRC of that library)
6  Inline .text patch in libc                           common    (most-verified library on device)
7  ArtMethod entry-point flip                           common    (the standard Xposed check)
```

Default tier (`max`) uses 1–3, and 4 only where a target is reachable no other way. `balanced` adds
5. `compat` adds 6 and 7.

**When you add a hook, your first question is "what is the lowest-numbered primitive that reaches
this surface?"** Not "what is easiest to write." The answer is frequently a GOT edge nobody thought
to look for — that is how the conscrypt wrap and the `adler32` interception were found, and both
replaced a louder design that worked.

---

## The architectural decision tree, with reasoning

### Why GOT/PLT rewriting is the primary primitive, not inline hooking

A GOT slot rewrite changes one pointer in a data page. The provider library's `.text` stays
byte-identical to the file on disk, so the memory-vs-disk CRC check that catches inline hooks finds
nothing. Detecting a GOT rewrite requires snapshotting the GOT at load and re-reading it, or
validating that each slot points inside its expected provider — real techniques, but far rarer in
the wild than text CRC.

Consequences that are easy to miss:

- The whole CRC-countermeasure problem (dump-post-hook-text, redirect disk reads, and ultimately a
  kernel module to catch direct `svc` syscalls) **does not arise at `max` tier**, because there is
  nothing for a text CRC to find. That is a large amount of Phase 2 engineering that the default
  configuration simply never needs. Do not undo this casually.
- The rewriter is ours, ~150 lines over `.rela.plt`. bhook can do it but brings a dlopen monitor and
  background threads into the target process. Rejected on footprint, not on quality.
- Only `.rela.plt` needs parsing: imported *function* symbols get `R_AARCH64_JUMP_SLOT` entries
  there, and `.rela.plt` is never packed by Android's SLEB128 relocation encoding (only `.rela.dyn`
  is). This is why the implementation stays small. If you ever need a *data* import, you will need
  the packed-relocation decoder; do not add it speculatively.

**Where GOT does not work**: provider and consumer in the same library, or linked `-Bsymbolic`. Then
no slot exists. `got::has_edge()` is how the module discovers this; the target falls to an inline
hook at `balanced` and the coverage ladder tells the user why.

### Why DEX-in-memory patching, not LSPlant / ArtMethod hooking

Unchanged from v1 and still the right call. LSPlant flips
`ArtMethod->entry_point_from_quick_compiled_code` to a trampoline; RASP detects this by checking
whether a method's entry point lies inside the legitimate `.oat` mapping. That is primitive #7, the
loudest thing on the ranking.

DEX patching rewrites the target method's bytecode before ART verifies it. ART then verifies our
bytecode (valid, passes) and compiles it normally. The resulting compiled code is *genuinely* a no-op
produced by ART itself — no trampoline, no entry-point anomaly, no foreign code mapping. The patched
method is indistinguishable from one originally written to do nothing.

**Do not** propose LSPlant for Phase 1 completeness. It is `compat`-tier, Phase 2, conditional, and
there is a real chance it is never built.

### Why the interception point is the `adler32` GOT slot in libdexfile

This is the least obvious decision in the project; do not "simplify" it without reading this.

`DexFileVerifier::CheckHeader` computes the DEX file's Adler-32 by calling zlib's `adler32` — a
cross-library call from `libdexfile.so`, so a GOT slot exists. Our replacement calls the original
first (getting the checksum of the *unpatched* bytes), patches the DEX, then returns the saved
original value. The verifier compares it against the untouched header field, they match, and
verification proceeds over the patched bytes.

Why not hook `art::DexFileLoader::OpenCommon`, which is the obvious choice and what v1 specified:

- `OpenCommon` needs an **inline** hook in libdexfile — primitive #5, text modified, CRC-detectable.
  The `adler32` edge is primitive #3.
- `OpenCommon` needs per-version knowledge of the `DexFile` object layout, and the LSPlant-family
  projects we copy symbol candidates from have **no DexFile symbol candidates to copy** — that part
  of v1's "just copy from LSPlant" plan did not exist.
- The `adler32` edge is one choke point covering the primary APK, feature splits, `DexClassLoader`
  and `InMemoryDexClassLoader`, because all of them are verified. v1 needed two separate hook
  families (`LoadClass` plus the `DexFile::Open*` family) to cover the same ground.
- **We never rewrite the header checksum.** v1 never mentioned the checksum at all, which would have
  been a shipped-and-broken Java path: ART validates it, and a patched DEX with a stale checksum
  fails verification outright.

**Its dependency, which is not optional**: the interception only fires when verification actually
runs, and ART skips the verifier when a vdex supplies `VerifierDeps`. That is why oat eviction
(below) is coupled to it. Neither mechanism works alone. If you disable one, the other silently
stops working — which is the worst failure mode available, so both get a coverage-ladder line.

`INLINE_IN_PROVIDER` on `OpenCommon` remains in the table as the `balanced` fallback for any Android
version where the `adler32` contract fails. Keep it there.

### Why oat eviction is companion-side, not an in-process hook

**This gap was absent from v1 entirely and would have made the module appear to work and then stop.**
When ART has compiled code for a method in the package's `.odex`, it runs that code and the DEX bytes
are irrelevant. A DEX patch works the day it is applied and dies after the next overnight
`bg-dexopt`.

The companion already has root and is already in the launch path, so it deletes the target package's
oat artifacts before replying to the hook request. ART then runs from the APK's DEX under interpreter
plus JIT. Cost: slower app start. In-process footprint: **zero**. That is primitive #2 beating the
in-process `stat`-hook alternative (primitive #3) on the ranking, so it is the default.

Two details that are load-bearing:

- It must be **deletion**, not `pm compile --reset` and not `--compiler-filter=verify`. A
  `verify`-filter vdex still carries `VerifierDeps`, ART skips `DexFileVerifier`, and the `adler32`
  interception never fires. We need *no vdex at all*.
- Secondary DEX (`DexClassLoader`, feature splits) has its own oat artifacts in the app's data
  directory. Enumerate and evict those too.

The in-process GOT hook on the `stat` family in an ART library stays as a configurable fallback for
read-only paths, unusual install layouts, and DEX opened mid-run. Note it hooks `stat` **in an ART
library's GOT**, never inline in libc.

### Why platform TLS is wrapped at conscrypt's `custom_verify` edge, and why four Java targets were deleted

**SUPERSEDED (2026-10-24)**: v1's Java target list included
`com.android.org.conscrypt.TrustManagerImpl`, `android.security.net.config.NetworkSecurityTrustManager`,
`android.net.http.X509TrustManagerExtensions`, and `javax.net.ssl.X509TrustManager`. All four were
unreachable by the stated mechanism and are removed.

- The first three are **bootclasspath** classes. They are preloaded in zygote and AOT-compiled into
  the boot image before our module exists. There is no class-load event left for us to intercept and
  no app-owned DEX containing them.
- `X509TrustManager.checkServerTrusted` is an **interface method**. There is no bytecode to patch.

That was a third of the v1 Java list, including every surface that mattered more than OkHttp.

The replacement reaches all of them with one GOT rewrite: `libjavacrypto.so` (conscrypt's native
library) calls `SSL_CTX_set_custom_verify` / `SSL_set_custom_verify` in the conscrypt APEX's
`libssl.so`. Cross-library call, so a slot exists. We substitute our callback for conscrypt's.

Everything that validates certificates through a `javax.net.ssl` `TrustManager` funnels through that
one edge: platform trust, Network Security Config pin-sets, TrustKit, Volley with a custom
`SSLSocketFactory`, gRPC over OkHttp, any app's hand-rolled `X509TrustManager`, and Cronet's default
system-trust path. None of it was reachable by DEX patching; all of it is reachable here.

**Wrap, do not replace.** Our callback invokes conscrypt's original first. If it fails, conscrypt has
a pending Java `CertificateException` from the `TrustManager`; we clear it via JNI and return
`ssl_verify_ok`. Replacing the callback outright is one line simpler and strictly louder, because the
app's `TrustManager` is then never constructed or invoked — and "was my trust manager actually
called" is a cheap check an app can make without any hook-hunting at all. The test app asserts the
`TrustManager` still ran.

**Consequence for the Java list**: what remains is pinning that runs *after* a successful handshake,
reading the negotiated chain. OkHttp `CertificatePinner` is the canonical case and the reason the DEX
path exists at all. If you are about to add a Java target, first check whether it is invoked as a
`TrustManager` during the handshake — if so, the conscrypt wrap already has it and the DEX target is
dead weight.

### Why a companion process is mandatory

**SUPERSEDED (2026-10-24)**: v1 had no companion. Its config loading (§1.7) and file logging (§1.8)
were specified as happening in `postAppSpecialize`, which cannot work.

Module code in `postAppSpecialize` runs as the app's UID in the `untrusted_app` SELinux domain. It
cannot read `/data/adb/pinning_haters/config.json` and cannot write to `/sdcard` under scoped
storage. A v1 build would have read no config and written no logs.

The companion runs as root in the Zygisk daemon. It owns config parsing, tier resolution, the log
sink, and oat eviction. The app-side module sends `{package, uid, api_level}` and receives a
fixed-size decision struct. This also means the target process performs **no file operations of ours
at all**, which is both quieter and simpler than the alternative.

Hot reload is unchanged in spirit: the companion re-reads the config on every request. Small file,
microseconds, no stale state.

### Why logs go to the companion, not `/sdcard`, and not logcat

**SUPERSEDED (2026-10-24)**: v1 put logs at `/sdcard/pinning-haters/log/<package>-<timestamp>.log`
and reasoned that our internal state is not sensitive enough to matter. The reasoning was sound as
far as it went; the decision is still reversed, for two reasons it did not consider.

1. The app process cannot write there. See above.
2. A world-readable log file is a trivially greppable indicator that this tool is on the device.
   Cheaper for an app to check than any hook-detection technique, and it works even when every other
   part of our stealth posture holds.

Logcat is rejected for reason (2) as well: an app can read its own process's logcat and grep for our
tag. Logs go over the companion socket to `/data/adb/pinning_haters/log/`, mode 0600, root-owned.
Default off. The WebUI reads them with root; Magisk users use `adb shell su -c`.

Rotation unchanged: delete files older than 7 days on companion start, cap the directory at 100 MB,
oldest first.

### Why `/proc/self/maps` filtering and friends are NOT in Phase 1

**SUPERSEDED (2026-10-24)**: v1 §1.9 items 1–4 specified filtering `/proc/self/maps`, `smaps`,
`status`, `dl_iterate_phdr`, `/data/adb/pinning_haters/*` and `getprop`.

Every one of those requires inline hooks on `open`, `openat`, `fopen` or `dl_iterate_phdr` in libc —
primitive #6, the most CRC-verified library on the device. They defend only against apps that are
already hunting for injected libraries, i.e. RASP, which Phase 1 deliberately does not engage. The
net effect on a non-RASP app is to make the module *strictly more detectable* than doing nothing: we
would be adding the loudest primitive on the ranking in order to hide from a check that app never
runs. v1's own "moderate stealth in Phase 1" reasoning argued against exactly this and then
specified it anyway.

Hiding our `.so` is the **host's** job. ZygiskNext, NeoZygisk and APatch+Zygisk already do it;
Magisk's built-in Zygisk does not. Magisk is therefore documented as a degraded host tier rather than
something we paper over. Prefer a host that hides module libraries if stealth is the priority.

The `/data/adb` hiding item is additionally self-defeating now: nothing in the target process ever
touches those paths, so the hook would create the exposure it was meant to remove.

These techniques return in Phase 2.2, where there is finally something shooting at them and where the
CRC countermeasures that make them survivable also exist.

### Why stealth tiers exist, and why `max` is the default

The project wants to be close to universal *and* as undetectable as possible, and those pull in
opposite directions for a minority of surfaces (Flutter, static stripped BoringSSL, Unity, Mono,
Dart-side pinning). Resolving it with a global compromise would make every user pay the detection
cost of the hardest app they have.

Instead: three tiers, a global ceiling, and a **per-package override**. The user raises the tier for
the one app that needs it and everything else stays at `max`. Universality comes from per-package
escalation, not from a loud default.

`max` is the default because of the priority order. A user who installs this and tests a
RASP-protected banking app will see it fail — and the coverage ladder will tell them which tier to
try, which is a better outcome than silently having been detectable the whole time.

Implementation rule: the tier is a **filter over a data table**, via `min_tier` on every target
entry. It does not branch code paths per target. This is what keeps the hooks-are-data rule intact
while supporting three tiers.

### Why the coverage ladder is a Phase 1 deliverable, not polish

A tier ceiling is only tolerable if the user can tell why a bypass failed. Without it, "nothing
happened" is indistinguishable from "wrong tier", "surface not present", "app uses a runtime we do
not support" and "bug". Presence detection is tier-independent and nearly free: noticing
`libflutter.so` is mapped costs a string compare over loaded library names and requires no hook.

Format and the user-facing surface→tier table are in plan §2.4 and `docs/coverage.md`. The WebUI log
viewer highlights these lines. This is the project's primary support-burden reducer; treat it as
load-bearing.

### Why hostname verification is a separate opt-in group

**SUPERSEDED (2026-10-24)**: v1 listed `org.apache.http.conn.ssl.AbstractVerifier.verify` among the
pinning targets. Hostname verification is not pinning.

An interception proxy presenting a certificate for the correct host does not need it relaxed, and
relaxing it by default weakens the target app further than the user asked for. Gated behind
`relax_hostname_verification`, default false.

### Why there is no denylist mode

**SUPERSEDED (2026-10-24)**: v1's config had `"mode": "allowlist" | "denylist"`.

A denylist means installing hooks in every process on the device, including `system_server`. That is
a bad idea on the priority order and a worse one operationally. Removed. `packages` is now an object
keyed by package name so per-package tier overrides have somewhere to live.

Default off, opt-in per package, empty `packages` — unchanged and still non-negotiable. The module
does nothing until the user names a package. Document prominently so "nothing happened after install"
is not a support ticket.

### Why config is NOT mirrored to sdcard

Unchanged from v1 and still correct. The config lists which packages the user is targeting. Mirrored
to `/sdcard`, any app with storage permission could read the user's hook list and check whether it is
on it. Root-only path, companion-mediated. The companion architecture makes this free rather than a
trade-off.

### Why telemetry is just a local log file

Unchanged. "Telemetry" and "logging" are the same thing for our purposes: structured records of what
the module did during an app launch. One format, one location, one config flag, no remote endpoint,
privacy by default. Users attach the file to issues, which gives the same diagnostic value remote
telemetry would have. If someone proposes remote analytics: no.

### Why no Frida

1. **Stated requirement at project inception.** Frida-based bypasses exist in abundance; being a
   non-Frida solution is this project's reason to exist.
2. Frida's footprint — the server process, the gadget, ptrace attachment, memory artifacts — is
   fingerprinted by RASP as a routine matter.

If a contributor proposes shipping frida-server with the module, decline.

### Why no LSPosed framework

Unchanged. LSPosed (and its fork Vector) is a fine project, but it brings an `lspd` daemon outside
our injection, hooks inside `system_server`, config databases at known paths, and a manager APK
visible to package enumeration. All detection surface a single-purpose tool does not need. If we ever
need ArtMethod hooks we use LSPlant directly as a library, without the framework.

### Why ARM64-only (x86_64 backlogged)

99%+ of physical devices are ARM64; x86_64 is mainly emulators. Adding it means per-architecture
GOT/relocation handling, inline-hook backends, ART struct layouts and a doubled test matrix.
Backlogged. ARM32 out of scope.

### Why shadowhook for inline hooks

Actively maintained, robust ARM64 inline and PLT/GOT handling, good docs, production use at
ByteDance. Dobby is stale; xHook/bhook are superseded for our needs. Note it is now a **`balanced`
tier dependency only** — `max` never calls into it. Compiled in but unreachable by default.

### Why GPL-3

1. Forces forks to stay open. Pinning bypass tools have a habit of being forked into closed
   commercial pentest tooling.
2. Compatibility with LSPlant (GPL-3) should Phase 2 ever need it.

shadowhook is Apache-2.0, which is GPL-3 compatible in that direction.

### Why no Rust

Our ecosystem (shadowhook, LSPlant, ART internals work, Magisk module templates) is C++. Mixing Rust
into a Zygisk module adds toolchain complexity for a small codebase. Contributors in this domain know
C++. If someone proposes a rewrite, the answer is no unless they are also volunteering to maintain
it.

### Why monorepo

Cross-cutting changes (a config field touching module and WebUI) land in one PR. One issue tracker,
one release. Split later if any part grows enough to warrant it, which is unlikely.

### Why we deliberately don't engage RASP in Phase 1

Phase 1 targets the apps without serious anti-tamper. They fall to the `max` primitives with no
exotic stealth. The remainder — banking, payment, government, DRM, some social — need per-vendor
reverse engineering plus maximal stealth, and that is Phase 2.

Mixing RASP defeat into Phase 1 would expand scope enormously, couple architecture to vendor-specific
concerns prematurely, and risk over-engineering for cases most users do not have. The phased approach
also lets Phase 1 gather real data on which vendors users actually encounter, which beats guessing.

One thing changed here: because `max` modifies no executable bytes, Phase 1 is accidentally much
closer to RASP-resistant than v1's design was. Do not treat that as a reason to engage RASP early —
treat it as the reason the tier boundary sits where it does.

### Why the recipe system might never be built

Unchanged. The subscribable signed YAML feed idea is elegant and deferred. Phase 1's hardcoded list
covers most apps; building the system right needs schema design, parser, sandboxing, signing and
feed distribution, easily a person-quarter; building it wrong is worse than not building it.

If you are considering it, **verify the demand first**: count "please add hooks for X" issues over a
six-month window. Dozens per month, build it. A handful, keep using PRs.

---

## Hard rules (do not violate)

### Verify ELF contracts, in CI, against real binaries

The `max` tier rests on three GOT edges existing. Each one is a hard dependency on another project's
build configuration, so each one gets a mechanical assertion rather than a comment.

`tools/check_elf_contracts.sh`, wired into `contract.yml`, asserts against
`tools/reference-libs/<api>/` for API 30, 31, 33, 34, 35, 36:

```bash
readelf -r libjavacrypto.so | grep -E 'SSL_(CTX_)?set_custom_verify'   # platform TLS wrap
readelf -r libdexfile.so    | grep adler32                            # DEX interception
readelf -r libdl.so         | grep -E '__loader_(dlopen|android_dlopen_ext)'  # deferred loads
readelf -r libart.so libartbase.so libdexfile.so | grep -E '\bstat(64)?\b|fstatat64'  # vdex probe
```

A new Android version that moves one of these fails CI instead of failing silently on a user's
device. This is why v1's §1.5.5 "version compatibility automation" was promoted out of Phase 1.5 into
Phase 1 — it is not a nice-to-have when the default tier depends on the contracts holding.

`tools/reference-libs/` is **gitignored** — do not commit Google's binaries. It holds `libart.so`,
`libartbase.so`, `libdexfile.so`, `libnativeloader.so`, `libjavacrypto.so`, `libssl.so` and, from
the runtime (bionic) APEX, `libdl.so` per API level, not just libart, because our contracts span
all of them (2026-11-03: `libdl.so` carries C3).

Extraction from Pixel factory images (`developers.google.com/android/images`):

1. Download the factory image zip for the target version.
2. Unzip; inside is `image-<device>-<build>.zip`. Unzip that; find `system.img`.
3. `simg2img system.img system.raw.img` if sparse.
4. `sudo mount -o loop,ro system.raw.img /mnt/sysimg`.
5. ART libraries: `/mnt/sysimg/apex/com.android.art/lib64/` (or `com.android.runtime` on early
   Android 10/11 — both names exist transitionally). Conscrypt:
   `/mnt/sysimg/apex/com.android.conscrypt/lib64/`. bionic's `libdl.so`:
   `/mnt/sysimg/apex/com.android.runtime/lib64/bionic/`.
6. If the APEX is a `.apex` file (a zip containing an image): `unzip`, loop-mount `apex_payload.img`,
   pull from there.
7. Save to `tools/reference-libs/<api-level>/`.

Backup sources, in order: `adb pull` from a stock Pixel; Android Studio AVD system images (symbol
names and relocation structure are identical between x86_64 and ARM64 from the same source tree, so
x86_64 AVDs are fine for *name* verification); GSI; AOSP self-build.

### Use the candidate-list pattern for ART symbols, and copy from projects that ship

Where mangled ART symbol names are still needed (the `balanced` inline fallbacks, the vdex-probe
library selection), do not hardcode one name. Each backend declares an array of candidates; the
resolver tries each in order at init and uses the first that resolves.

```cpp
// art_contracts.cpp
static const char* kOpenCommonCandidates[] = {
  "_ZN3art14DexFileLoader10OpenCommon...",   // AOSP 13.0, verified against Pixel factory image
  // vendor variants appended as GitHub issues report them
  nullptr
};
```

Symbol discovery is mostly already done by other GPL-3 projects. Copy their candidates with
attribution, then verify. In rough order of usefulness:

1. **LSPlant** (`github.com/LSPosed/LSPlant`) — authoritative for ClassLinker and ArtMethod.
   `lsplant/src/main/jni/art/runtime/`, files like `class_linker.hxx`, `art_method.hxx`.
2. **Vector** (`github.com/JingMatrix/Vector`) — active LSPlant fork, newest version coverage.
3. **LSPatch** (`github.com/LSPosed/LSPatch`) — closer to our class-loading-time use case.
4. **Pine** (`github.com/canyie/pine`) — cross-reference. If LSPlant and Pine agree, it is right.
5. **SandHook** (`github.com/asLody/SandHook`) — older, occasional extra fallback names.

Note the limit discovered while writing the v2 plan: **none of these carry DexFile/DexFileLoader
symbol candidates.** v1 assumed they did. That absence is a large part of why the `adler32` GOT edge
is the primary DEX interception point — it needs no ART symbol at all.

Source code from maintained projects is not an "online source" in the sense we distrust: it compiles,
runs and is tested against real devices. Blog posts and Stack Overflow answers with hand-typed
100-character mangled names are. Verify anything from the latter with `nm -D` before shipping.

### Graceful degradation, always

Resolution failure is never a hard failure. At init, try to resolve every contract and symbol. On
failure, log it with `ro.product.manufacturer`, `ro.build.version.release` and
`ro.build.version.security_patch`, emit a coverage-ladder line, and continue with whatever did
resolve.

The degradation order is worth knowing, because the surfaces are not equally valuable: if the
conscrypt wrap resolves but the DEX path does not, the user still gets all TrustManager-based pinning
(platform trust, NSC pins, TrustKit, custom trust managers) and loses OkHttp `CertificatePinner`. If
the DEX path resolves but the conscrypt wrap does not, they get far less. The conscrypt wrap is the
single most valuable hook in the project; prioritise its contracts accordingly.

### Test each release against the manual matrix before tagging

No release ships without passing the matrix on at least three Android versions across at least two
root managers. Documented in `docs/testing.md`. This is annoying when a one-line fix feels like it
should ship instantly. Do not skip it. Silent breakage on Android 14 because we only tested 13 is
exactly the failure mode it prevents.

Additionally, and specific to this architecture: **release verification includes the zero-modified-
executable-bytes check** (plan §1.16 item 6). CRC every mapped library's executable segment against
its file on disk from inside a target process at `max` tier, and assert equality. The headline
property gets a mechanical check, not an assertion in a README.

### Default off, opt-in per package

Empty `packages`. The user adds packages explicitly. No exceptions.

### No remote callbacks, no analytics, no auto-updates

The module fetches `update.json` only when the host module manager checks it, and only to display an
update notification. It does not phone home otherwise, does not POST anything anywhere, and does not
auto-update. Do not add network functionality without project-owner approval.

### Hooks are data, not code

Adding a pinning surface means adding entries to `targets_java.cpp` or `targets_native.cpp`. It must
not require per-target C++ logic. If you want to write per-target code, the data structure needs
extending instead — propose a new field on `JavaTarget` / `NativeTarget`.

This now explicitly covers primitive selection: `NativeTarget::style`
(`GOT_IN_CONSUMER` | `INLINE_IN_PROVIDER` | `PATTERN`) and `min_tier` are **data**. The hook manager
picks the quietest listed style that resolves and is permitted by the tier ceiling. "Prefer GOT, fall
back to inline" is a property of the table, not a branch in a target's handler. This rule is what
makes three tiers survivable as the hook list grows.

### Documentation updates ship with code changes

New hook target → update `docs/adding-hooks.md` if the workflow changed, and `docs/coverage.md` if a
new `SurfaceId` appeared. New Android version → `docs/android-versions.md`. Config schema change →
`examples/config.example.json` **and** `README.md`. New tier-gated capability →
`docs/stealth-tiers.md`.

Out-of-date docs in a security-sensitive project actively mislead users. Docs are part of the
deliverable.

---

## Things that will look wrong but are intentional

### The Java target list is four entries long

Correct. Everything that used to pad it out is reached by the conscrypt `custom_verify` wrap, more
cheaply and in places DEX patching cannot go. See "Why platform TLS is wrapped..." above. Before
adding a Java target, check whether it runs as a `TrustManager` during the handshake — if so it is
already covered.

### We nop-fill the entire remainder of `insns[]` after the replacement

Not laziness about cleanup — a correctness requirement. `DexFileVerifier` does a **linear sweep** of
the whole instruction array, not a reachability analysis. If our 2-byte `return-void` lands where a
4-byte instruction began, the byte at offset 2 is the second half of that instruction and the sweep
hits an invalid opcode, verification fails and the class is rejected.

**SUPERSEDED (2026-10-24)**: v1 said to leave trailing bytes alone because "ART won't execute past
`return`". True of execution, false of verification. Filling to `insns_size` with `nop` (`0x0000`)
keeps the sweep valid and keeps every `try` / `catch` address on a legal instruction boundary.

### We never change `insns_size`

Deliberate. Leaving it alone sidesteps the `tries[]` / `handlers[]` offset-shifting problem
completely. Combined with nop-filling, the code item stays structurally identical and only the
instruction bytes differ. Require `insns_size >= units_needed` and bail with a log if not.

### We do NOT `madvise(MADV_DONTNEED)` before writing to DEX pages

**SUPERSEDED (2026-10-24)**: v1 did this and v1's AGENTS.md defended it as deliberate. It was wrong
on both counts.

App DEX mappings are created after fork and are not shared with zygote, so there is no shared mapping
to detach. Worse, on an anonymous mapping — which is where a DEX extracted from a compressed APK
entry lives — `MADV_DONTNEED` **zero-fills the page and corrupts the DEX**. `mprotect` to RW, write,
`mprotect` back is sufficient and correct; the mapping is `MAP_PRIVATE`, so the write copies on write
and touches neither the file nor another process.

If you see `madvise` reappear near DEX writing, it is a regression.

### `RETURN_FIRST_ARG` is not implemented

All four of its v1 consumers (`verifyChain`, `X509TrustManagerExtensions.checkServerTrusted`, etc.)
were bootclasspath targets that have been removed. The replacement kind has no users, so it has no
implementation. If a future target needs it: `p0` is `this` for instance methods, so the first
explicit argument is `p1`, and the register number comes from `registers_size` minus `ins_size` in
the code item header. Unit test it on the host before shipping.

### We read `dl_iterate_phdr` but never hook it

Reading it is how the GOT rewriter locates a library's load bias and `PT_DYNAMIC`. Hooking it to hide
ourselves was cut (see the `/proc/self/maps` entry above). Reading is free and invisible; hooking
costs a libc inline patch.

### Logging a surface as `present=no` is normal

The target table covers many libraries (OkHttp 3/4/5, curl, gRPC, Cronet, Flutter, Unity...). Most
apps ship few of them. `present=no` lines are expected and are not errors. `present=yes
reachable=no` lines **are** actionable — they mean the tier ceiling is blocking a surface the app
actually has, and they name the tier that would reach it.

### App start is slower for target packages

Oat eviction means the app runs interpreted plus JIT for that launch. This is the cost of the DEX
path working at all, and it is a deliberate trade. Document it in `docs/known-limitations.md` so it
is not reported as a bug.

### Module init logs the Android version, selected contracts and effective tier even in release builds

Intentional. When a user attaches a log to an issue, knowing which contracts resolved and at which
tier the module ran is the single most useful piece of context. It contains nothing sensitive and the
log is root-only anyway.

### The WebUI doesn't authenticate the shell bridge

It cannot. The WebUI runs in the host module manager's WebView, which has already established the
user's root context. Anything the WebView can ask, the user already has root for. There is no
meaningful additional authentication available.

### Magisk Manager users have a worse UX, and a worse stealth posture

Two separate things, both documented. No WebUI support, so config is edited via `adb shell su -c`.
And Magisk's built-in Zygisk does not hide module libraries, so our `.so` is visible in
`/proc/self/maps` as a memfd mapping — see the host tier table in plan §0. We do not paper over the
second one with libc hooks; the fix is to use a host that hides module libraries.

---

## Style and conventions

- **C++20**, no later (NDK constraint).
- **No exceptions** in hook code paths. Failure → log, emit a coverage line, return false.
- **No global mutable state** outside explicit singletons (resolved contracts, hook manager). The
  per-app decision struct lives on the stack of `postAppSpecialize`.
- **No threads** created in the target process, ever.
- **snake_case** for filenames and functions, **PascalCase** for types, **SCREAMING_SNAKE** for
  constants.
- **Comments explain why, not what.** Especially for the two non-obvious interception points: the
  `adler32` trick and the conscrypt wrap-not-replace choice. A future reader will try to simplify
  both; leave them a reason not to.
- **New files start with a GPL-3 license header.**
- **Magic numbers get named constants**, especially DEX opcodes — `dex/dex_format.h`.
- **Every new target entry carries `min_tier` and `surface`.** A target without a `SurfaceId` is
  invisible to the coverage ladder, which makes it undebuggable in the field.

---

## Threat model boundaries (who we're not for)

- **Not a malware-development tool.** Refuse features that only make sense for malicious use: covert
  payload injection, persistence beyond what the module needs, exfiltration. This is for traffic
  inspection of apps you are authorised to test.
- **Not effective against TEE-backed pinning.** Hardware-attested chains validated inside
  TrustZone/StrongBox cannot be bypassed by anything running in the REE. Permanent limitation.
- **Not effective at `max` against** statically linked and symbol-stripped BoringSSL that does not
  carry the `ssl_crypto_x509_method` table shape the Flutter locator keys on, or libraries with no
  usable GOT edge. Those need `balanced`. (Flutter's internal verification *is* reached at `max`
  since 2026-10-25; see "Phase 1.5, Flutter".)
- **Not effective at any current tier against** Dart-side pinning packages, Unity IL2CPP custom
  pinning, or Xamarin/Mono `ServerCertificateValidationCallback`. Those are AOT-compiled foreign
  runtimes, `compat`-tier, Phase 2.
- **Not able to reach kernel-level coverage of the CRC countermeasure.** A purely Zygisk-resident
  module cannot intercept a RASP that issues `openat` via raw `svc`. That requires a companion
  kernel module and is a documented boundary, not a gap we will quietly close.
- **Not a replacement for reviewing your own app.** Developers debugging their own apps should use
  `network_security_config.xml` debug-overrides. This tool is for apps you do not have source for.
- **Not a replacement for installing your proxy CA.** For target packages the conscrypt wrap accepts
  any chain so no CA install is needed; for broad non-targeted interception, installing the CA as a
  system CA via a separate module is quieter than targeting every package here.
- **Not stealthy against actively-defended apps** until Phase 2. `max` is quiet, not invisible: GOT
  snapshot comparison, in-memory-DEX versus APK-DEX comparison, and noticing absent oat artifacts all
  work against it. Say so plainly in `docs/threat-model.md`.

---

## When to escalate to the project owner

Do not decide these alone:

- Making the **default** tier louder, or changing which primitives a tier permits.
- Adding a major new dependency beyond what is in `third_party/`.
- Changing the license.
- Changing the ARM64-only / x86_64-backlog scope.
- Adding network functionality of any kind.
- Restructuring phase boundaries (moving items between Phase 1 / 1.5 / 2).
- Adding RASP-defeat hooks to Phase 1.
- Anything that changes the privacy posture or the threat model.
- Shipping a surface whose ELF contract has not been verified on at least one real device.

For everything else — adding targets, fixing bugs, polishing docs, expanding the matrix, improving
the WebUI, refining the coverage ladder — proceed.

---

*Revised 2026-10-24 alongside the v2 plan. Future sessions: add to this file as decisions get made,
keep the format, and do not delete entries — supersede them with newer ones and note the supersession
date, as was done above.*

---

## Implementation-session decisions (2026-10-24, Phase 0 / 1 code drop)

Recorded while the Phase 1 code was written. Same convention: supersede, do not delete.

### Zygisk API v4 header, not v5

`module/jni/zygisk.hpp` is the v5 header from zygisk-module-sample with `ZYGISK_API_VERSION` set to
4 and the v5-only `mount_sysprop_overrides` field removed. The `api_table` layout is identical
between v4 and v5; declaring v4 is what lets ZygiskNext/NeoZygisk/APatch builds that predate v5
load the module. Bump only when a v5-only API is actually needed.

### The deferred-load edge is in `libnativeloader.so`, not `libart.so`

The plan (§1.8) said "GOT-hook `android_dlopen_ext` in `libart.so`". `JavaVMExt::LoadNativeLibrary`
calls `android::OpenNativeLibrary` in **libnativeloader.so**, and that is where the
`android_dlopen_ext` call — and the slot — lives. API 34 reference libraries show the slot in both
`libnativeloader.so` and `libart.so`; the table lists both as candidates and hooks every candidate
that has the edge. Still a GOT write in an ART APEX library, still `max`.

### Candidate lists are `|`-separated `consumer_library` strings, and every candidate with the edge is hooked

Rather than a separate `art_contracts.cpp` with per-backend arrays, the per-version library
candidates live in the data table: `"libartbase.so|libart.so|libdexfile.so"`. The manager hooks
every candidate that has the import, because for the oat-probe and dlopen edges we do not know
which ART library does the call on a given release and hooking all of them is idempotent (same
provider function, same original). `art_contracts.cpp` returns when a *symbol* candidate list is
needed (Phase 1.5 inline fallbacks); nothing in Phase 1 needs one.

### shadowhook is not vendored in Phase 1

The plan's tech stack said "compiled in, but only reachable at `balanced`". Compiled-in-but-
unreachable still adds the library's code and data to every target process's mapping of our `.so`
for zero Phase 1 benefit, and §1.11's "verify shadowhook creates no RWX pages" becomes a
Phase 1.5 item at the same time. `INLINE_IN_PROVIDER` and `PATTERN` entries remain in the table so
the coverage ladder reports `reason=backend_unavailable required_tier=balanced` today. The
submodule, the backend, and the RWX check arrive together with Phase 1.5.

### The app process reads no system properties; the companion supplies `api_level`

`__system_property_get` can lazily map a property-context file; the companion already has the
values, so they travel in the `Decision` (`api_level`, `build` string for the init log line).

### Companion socket lifetime follows `log.enabled`

With logging off (the default) the socket is closed right after hook installation, so a target
process holds no extra descriptor. With logging on it stays open for the process lifetime: DEX
patches happen at class-load time and deferred loads happen whenever the app says, and both need a
sink. The user opting into logs accepts the one socket fd. `connectCompanion()` cannot be called
after specialization, so there is no "reconnect when needed" option.

### The oat-probe fallback hides only `/data/**/oat/**.{odex,vdex,art}`

Boot-image and framework artifacts live under `/apex` and `/system` and must keep resolving.
Consequence: the platform's dexpreopted `org.apache.http.legacy` is not reached by the DEX path;
the Apache hostname-verifier entries only fire when the app bundles its own copy.

### Reference libraries come from AVD system images via `debugfs`, not factory images

`tools/pull_reference_libs.sh` downloads Google's `google_apis` arm64 system image for an API level,
locates the system ext4 partition (raw, GPT, or inside `super`), dumps the ART and conscrypt APEX
containers with `debugfs`, unwraps compressed APEXes, and dumps `lib64/` from the payload. No root,
no loop mounts, scriptable in CI with a per-API cache. The APEXes are the same mainline builds the
factory images ship; a factory-image pull remains valid and is documented as the manual route.

### The `adler32` interception keeps a table of patched DEX bases

Anything that re-checksums an in-memory DEX we patched (`DexFile::CalculateChecksum` paths) gets
the pre-patch value back. 64 entries, keyed by base+size. Not a correctness requirement for the
verifier itself — it only calls once — but it closes a "mismatch logged later" path cheaply.

### Exported symbols are exactly two

`exports.map` makes `zygisk_module_entry` and `zygisk_companion_entry` the only dynamic symbols.
Without it libc++ template instantiations leaked as weak exports, which is a free fingerprint.

### Cronet is NOT reached by the conscrypt wrap

**SUPERSEDED (2026-10-24, same day)**: the "Why platform TLS is wrapped..." entry above and plan §3.2
list "Cronet's default system-trust path" among the surfaces the `custom_verify` wrap reaches. It
does not. Cronet statically links its own BoringSSL inside `libcronet.*.so` and verifies chains by
calling up into Java (`X509Util.verifyServerCertificates` → `X509TrustManagerExtensions`) from its
own code, never through conscrypt's `cert_verify_callback`. There is no conscrypt SSL object in the
path, so the wrapped callback never runs. The table already treats Cronet as a `balanced` pattern
target (`libcronet.*` runtime marker); docs follow the table. Platform trust *in a Cronet app* is
therefore unreached at `max` until the Phase 1.5 pattern backend exists.

### `libssl.so` / `libcrypto.so` are not always in the conscrypt APEX payload

On API 34 (and presumably later) the conscrypt APEX's `lib64/libssl.so` is a symlink into the
`sharedlibs` APEX (`/apex/sharedlibs/lib64/libssl.so/<hash>/libssl.so`). The contract checks only
read `libjavacrypto.so`'s imports, so `tools/extract_apex_libs.py` reports the two as missing and
moves on. If a future contract needs the provider's exports, dump `com.*.android.sharedlibs.apex`
as well.

### `contract_missing` is reported per surface, not per entry

conscrypt imports `SSL_set_custom_verify` but not `SSL_CTX_set_custom_verify`; both are in the
table so a future conscrypt that switches is still caught. A missing edge is logged as
`reason=contract_missing` only when no other entry for the same surface rewrote a slot; otherwise it
is an optional variant and goes to the verbose log. Without this rule every launch on every current
Android would print one false contract failure.

### Review-driven corrections (2026-10-24, adversarial review of the first code drop)

- **Deferred loads evaluate every newly mapped library, not the one named in `android_dlopen_ext`.**
  `System.loadLibrary("native-lib")` maps `libnative-lib.so` *and* its `DT_NEEDED` chain
  (libcurl → libssl → libcrypto) in one call; the slots that matter are in the dependencies. The
  manager re-snapshots after each dlopen and evaluates libraries whose load bias it has not seen.
- **`*.dm` files are evicted alongside oat artifacts.** A DexMetadata file can carry a vdex, and
  `OatFileAssistant` falls back to it when `base.odex`/`base.vdex` are gone — which would skip the
  verifier exactly like a vdex does. The stat fallback hides `/data/app/**.dm` too.
- **The oat-probe rule now covers `/oat/` artifacts on every partition except `/apex`**, so system
  and priv-apps (read-only oat, nothing to evict) still reach the DEX path through the stat fallback.
  `/data/dalvik-cache/` stays untouched: boot-image extensions live there. The companion flags
  packages with no `/data/app` directory (`FLAG_SYSTEM_APP`) and the ladder reports `reason=system_app`.
- **16 KiB-page compat mode.** bionic's compat loader (4 KiB-aligned ELF on a 16 KiB kernel) keeps
  RO+RX+RELRO as one RX mapping and a RELRO tail that shares a page with `.data` as RW. Restoring a
  GOT page to plain `PROT_READ` there would fault the next text or data access; the rewriter detects
  compat mode (page size > 4 KiB and a `PT_LOAD` with smaller alignment) and restores RX / RW instead.
- The patched-DEX table also compares the header checksum before answering, so a different DEX mapped
  at a reused address is never handed a stale value; a v41 container range beyond the verified bytes
  is checked with `mincore` before any offset in it is trusted; the companion validates the package
  name before building a log path and serialises `nftw` state across concurrent requests.
- Open test item, not verifiable from the host: writing to the companion socket *after*
  specialization from the `untrusted_app` domain. Magisk's policy is expected to allow it; the first
  device run with `log.enabled=true` must show the `[init]` line or logging is silently dead.

### Device findings (2026-10-25, Redmi K20, Android 11 / API 30, APatch 11039 + Zygisk Next 1.4.5)

- **The log channel is a pipe the app process creates before specialization; the companion gets
  the read end.** SUPERSEDES the "Companion socket lifetime" entry above in one detail. Three SELinux
  facts, all observed on device, shape this: (1) the Zygisk companion socket is created inside the
  app process while it carries zygote's label, and once specialized `untrusted_app` may not write to
  it (`avc: denied { write } ... tcontext=u:r:zygote:s0 tclass=unix_stream_socket`); (2) a socketpair
  created by the companion is magisk-labelled and the zygote-labelled app process may not *receive*
  it over SCM_RIGHTS (`avc: denied { read write } ... tcontext=u:r:magisk:s0`, fd silently dropped);
  (3) a pipe created by the zygote-labelled process stays writable from `untrusted_app` (root-side
  probe: pipe created-as zygote → write OK; socketpair created-as zygote → denied; `magisk_file` fd →
  OK; `adb_data_file` fd → denied). So with `log.enabled` the module calls `pipe2()` in
  `preAppSpecialize`, sends the read end to the companion with SCM_RIGHTS (magisk may use zygote fds),
  keeps the write end (`exemptFd`), and closes the Zygisk socket. Writes are ≤ PIPE_BUF so they stay
  atomic across threads, and the sink polls for POLLERR before each write so a vanished companion
  cannot SIGPIPE the app. Everything else in that entry stands: no descriptor is kept when logging is
  off. ZygiskNext passes SCM_RIGHTS through unchanged; only policy, not the host, blocked direction (2).
- **Phase 0.5 items 4, 5 and 6 hold on API 30.** With `tests/test-app` targeted at `max`:
  `custom_trustmanager PASS` (handshake completes and the app's `X509TrustManager` observed being
  invoked — the wrap, not a replacement), `nsc_pins PASS`, `okhttp_pinner PASS` (the `adler32`
  interception fired and the DEX patch held after the companion evicted `base.odex/.vdex/.art`,
  `oat_evicted=2`), `untrusted_chain PASS` (untrusted-root.badssl.com), `post_handshake_digest FAIL`
  as designed. `tech.httptoolkit.pinning_demo` had its three oat artifacts evicted and all three GOT
  slots (`SSL_set_custom_verify` in libjavacrypto, `adler32` in libdexfile, `android_dlopen_ext` in
  libnativeloader) point into our library; the same slot in a non-target process (systemui) still
  points into the conscrypt `libssl.so`.
- **Zygisk Next 1.4.5 does not hide the module library path** on this device: `/proc/self/maps` of the
  target shows `/data/adb/modules/pinning_haters/zygisk/arm64-v8a.so` (and `libzygisk.so`). The host
  tier table's "hidden by host" claim needs the host's own denylist/hiding feature enabled for the
  target; record per-host behaviour in docs rather than assume it. Measured consequence: the generic
  detector app reports `Found Injection` when targeted and
  not when untargeted; all its other findings (Magisk, LSPosed, mounts, fingerprint) are the device's
  environment, not us. This is the one `max`-tier signal a non-RASP detector picked up, and it is
  entirely the visible library path — a Phase 2 item (host hiding or self-remap), not a Phase 1 fix.
- **HTTP Toolkit's SSL Pinning Demo through Burp is the real-world control**: untargeted, every pinned
  button fails against the proxy; targeted at `max`, Config (NSC), Context (custom TrustManager),
  OkHttp `CertificatePinner`, Volley and TrustKit all pass, while Appmattus CT interceptors and the
  raw custom-pinned socket stay red — exactly the Category A gaps the plan lists for Phase 1.5 /
  per-app targets. Per-button table in `docs/android-versions.md`.
- **An app cannot open `/proc/self/mem`** under `untrusted_app` (EACCES), so the executable-bytes
  release check in the test app hashes mapped memory through a 20-line JNI helper instead.
- The ART APEX file on this Android 11 build is `com.android.art.release.apex`; the extractor's
  name-pattern matching exists because of it.

### `INTERCEPTOR_PROCEED` (2026-10-25): the first replacement kind that is not a constant return

The demo's two red buttons were OkHttp interceptors (appmattus CT). An interceptor must return a
`Response`, so no constant template works; the body becomes `return chain.proceed(chain.request())`,
with the two `okhttp3.Interceptor$Chain` method ids resolved from the DEX being patched. Design
rules that fell out of it: `/range` invoke forms only (parameter registers above v15 exist in real
methods), v0/v1 as scratch (`this` is dead once we own the body), and a hard check that
`outs_size >= 2` because the verifier rejects an invoke wider than `outs_size`. The kind is still
data: a target names it, the patcher resolves what it needs, nothing per-target in C++. Any future
"return an object" kind (WebView's `X509Util` is the next candidate) follows the same shape:
resolve type/method ids by name, emit a fixed program, fail with a named reason if absent.

The interceptor alone turned one of the demo's two CT buttons green. The other (CT as a
`HostnameVerifier` wrapper) needed a different lever, and the one chosen is instructive: appmattus
gates every variant on a private `enabledForCertificateTransparency(host)`, so `RETURN_FALSE` there
disables CT library-wide without relaxing the delegate hostname check — patching the verifier's
`verify()` to `true` would have. Private method names survive in this app's DEX; the interceptor
pass-through remains as the fallback for R8-renamed builds. Both buttons green, `applied=2/2`.

### Chromium (WebView / Cronet / HTTP/3) is reached at `max` through the provider's DEX (2026-10-25)

The plan filed Cronet and WebView under "needs `balanced`" because their TLS stack is Chromium's own
BoringSSL. The chain *verification*, though, is Java: native `CertVerifyProcAndroid` calls up into
`org.chromium.net.AndroidNetworkLibrary.verifyServerCertificates` (older builds `X509Util`), which
lives in the WebView provider APK's DEX, or in the app's Cronet DEX — not in the boot image. That
DEX is loaded into the target process and, with its own oat artifacts hidden by the stat fallback
(`/data/app/.../com.google.android.webview-*/oat/`), goes through `DexFileVerifier`, so the
`adler32` interception patches it like any app DEX. The method returns an object, hence the
`RETURN_NEW_INSTANCE` kind: `new AndroidCertVerifyResult(0)` means status OK, empty verified chain
(native keeps the original chain) and `is_issued_by_known_root=false` (no pin enforcement). Both
R8 obfuscation facts matter: the class and the `@CalledByNative` method keep their names, the
constructor survives as `<init>(I)V` (checked with `tools/dex_methods.py` on WebView 156), while
`X509Util` itself is renamed — which is why `AndroidNetworkLibrary` is the primary target.
Consequence for the stat fallback: it is no longer only a fallback for odd installs; it is what
makes shared-library DEX (WebView, Cronet feature splits) reachable, since companion eviction only
touches the target package's own artifacts.

**SUPERSEDED the same day, mechanism only**: `new AndroidCertVerifyResult(0)` does not work. Native
`VerifyFromAndroidTrustManager` treats "status OK with an empty verified chain" as
`CERT_STATUS_INVALID` (WebView reported `SslError` 5), and R8 removed the three-argument
constructor that could carry a chain, so no fabricated result satisfies it. The shipped kind,
`CHROMIUM_TRUST_LEAF`, keeps Chromium's real verifier and changes what it trusts: the body becomes
`addTestRootCertificate(certChain[0]); return <inner static verifier>(args...)`. `addTestRootCertificate`
is Chromium's own test hook (`@CalledByNative`, name-stable, feeds `sTestCertVerifier`), the inner
verifier is the R8-renamed `X509Util.verifyServerCertificates` found by signature among *static*
methods (its instance twin `CertificateVerifier.verifyServerCertificates` shares the proto), and a
leaf that is itself a trust anchor validates as a one-certificate chain. Native then gets a real
non-empty chain, `is_issued_by_known_root=false`, no pins. Costs: one test-store entry plus one
trust-manager rebuild per TLS handshake in that process, and an unguarded Java exception from
`addTestRootCertificate` would reach jni_zero's CHECK (the inputs are certificates native has just
parsed, so this is theoretical). `RETURN_NEW_INSTANCE` stays in the tree as a generic kind.

### Templates relocate the method's try ranges and repoint in-template handler addresses (2026-10-25)

Found on device, not on the host: WebView's `verifyServerCertificates` has a catch handler at code
unit 5. After the 7-unit `RETURN_NEW_INSTANCE` program, unit 5 was the middle of an
`invoke-direct/range`, and ART rejected the whole class — `Verifier rejected class
org.chromium.net.AndroidNetworkLibrary: ... exception handler starts at bad address (5)` — which
took every `@CalledByNative` lookup on that class down with it (`jni_zero` CHECK-fails on
`getCurrentDnsStatus`, SIGTRAP). The nop-fill rule only covered addresses *after* the template.

The fix is uniform for every kind (`relocate_tries`): each `try_item` is moved onto the nop tail
(one unit each, ascending, so the structural verifier's ordering rule holds) and any handler address
that fell inside the template is rewritten in place to the first nop, keeping the ULEB128 byte
length (padding continuation bytes are legal). Sizes never change: `tries_size`, the handler list
layout and `insns_size` stay as they were, which keeps `DexFileVerifier`'s contiguous code-item walk
intact — shrinking `tries_size` would have broken that walk, so it was not an option. Moving the try
ranges also matters for a second reason: a handler whose address happened to be a boundary *inside*
the template would be reachable from the template's own throwing instructions, and the verifier
would then simulate a suffix of the template with the try block's register state. On the nop tail
nothing throws, so handlers are dead and never simulated. Host fixtures now carry try blocks that
collide with each template, and d8's re-dex of the patched fixture checks the result.

### Phase 1.5, Flutter (2026-10-25): a pointer-table swap, not an inline hook

The plan said "shadowhook + pattern-located inline hook on `ssl_crypto_x509_session_verify_cert_chain`".
What shipped modifies no executable bytes, and the reasoning is worth keeping because the inline
design will look simpler to the next reader.

- **The write is a data pointer.** dart:io installs a classic `SSL_CTX_set_verify` callback, so every
  Flutter handshake's chain check goes through BoringSSL's `ssl_verify_peer_cert` →
  `ssl->ctx->x509_method->session_verify_cert_chain`. That member lives in `ssl_crypto_x509_method`,
  a `const` struct of function pointers in `.data.rel.ro`. Swapping it has the detection profile of a
  GOT slot (primitive #3/#4), not of a `.text` patch (#5). The swap reuses the GOT rewriter's
  `hook_slot` path, so it is idempotent, RELRO-aware and restorable.
- **No symbol, so the function is found from the strings it references.** It is the only *code* that
  references both `"ssl_client"` and `"ssl_server"` (its `X509_STORE_CTX_set_default` call) — except
  libcrypto's `X509_VERIFY_PARAM_lookup`, a `strcmp` chain over the same literals. The two are told
  apart by the table: only ours is reached through a RELRO pointer. The locator decodes ADRP+ADD pairs
  for each string instance, takes every candidate reference, and keeps the one for which a RELRO
  pointer lands at most 4 KiB before it inside a run of other code pointers. A `mov wN,#0x50; strb
  wN,[x2]` prologue (`*out_alert = SSL_AD_INTERNAL_ERROR`) is a tie-breaker only. More than one
  survivor → refuse, log, `backend_unavailable`.
- **lld folds `.rodata` into the R+X segment** in Flutter's build. The first locator skipped executable
  segments when searching for strings and found nothing; it now searches every readable segment.
- **Wrap, do not replace**, for the same reason as conscrypt: the original runs `X509_verify_cert` and
  Dart's `CertificateCallback`, so an app's `badCertificateCallback` still fires with its side effects;
  only the boolean is overridden. BoringSSL looks at nothing else (`session->verify_result` keeps the
  real error and Dart never reads it).
- **It is `max`.** SUPERSEDED the same day: the first cut kept it at `balanced` because the slot is
  found by heuristic rather than by a CI-verified contract and because the plan had placed Flutter
  there. The owner's rule (2026-10-25): if a surface can be had at `max` without reducing stealth, it
  goes to `max`; per-app tiers exist only for coverage that costs stealth. A RELRO pointer in an
  app-private library is the same class as the bundled-TLS GOT edges `max` already uses, so it
  qualifies. The heuristic's safety net is `tests/host/test_flutter` over real engine builds, the
  analogue of the ELF contract check. The surface is gated by `surfaces.bundled_tls` (Flutter *is*
  bundled TLS), not by `foreign_runtime`, which now means Dart-side/IL2CPP/Mono only.
- **shadowhook is still not vendored.** Nothing in the table needs an inline hook today; the
  `INLINE_IN_PROVIDER` entries keep reporting `backend_unavailable`. Vendor it when an entry needs it,
  together with the RWX-page check.
- **Host test over real engines.** `tests/host/test_flutter` loads a `libflutter.so` *file* the way the
  linker would (PT_LOADs at their vaddrs, `R_AARCH64_RELATIVE` applied — Flutter links plain RELA,
  not RELR or APS2, so the file slots are zero until relocated) and runs the real locator. Fixtures:
  the demo 1.7.1 and the Flutter bank app engines under `tools/reference-libs/flutter/` (gitignored). Their
  offsets matched the device log byte for byte.
- **Testing Flutter needs traffic steering.** `dart:io` ignores the Android HTTP proxy setting and
  user CAs. The discriminating device test used `iptables -t nat ... -m owner --uid-owner <uid> -j DNAT`
  to send the demo's TCP 443 to `untrusted-root.badssl.com`: red at `max`, green at `balanced` with
  the `verdict overridden` line. Burp's `self_signed` listener mode produced a TLS handshake failure
  (alert 40) through the REST config and `static_hostname` would not start, so an untrusted-cert
  listener was not available; the badssl redirect needs neither. The Flutter bank app's pre-login traffic, steered
  to Burp's invisible listener, was accepted by its `dart:io` from the system store without any
  override — it does not pin at the BoringSSL level; whatever Dart-side checks it has (`dart_pinning`)
  were not exercised before login.

### Companion tombstones that are not companion bugs (2026-10-26)

Five `zn-zygisk-companion64 pinning_haters` tombstones from 2026-10-25, all `SIGSEGV` at a small
address with `pc` equal to that build's `.plt` start and frame #1 inside `companion_main`, each one
a few seconds after a rebuilt `arm64-v8a.so` had been `cp`'d over the live module file. The
companion thread was parked in `serve_log` for a running target; `cp` replaced the file's pages
under the mapping; the new text's PLT stubs read `.got.plt` at an offset the old process had never
copied-on-write, so the slot still held the linker's initial file-relative PLT0 pointer. A reboot
with the file untouched, followed by a target launch, produced no tombstone and a stable companion
pid. Install through a new inode (`mv`), never `cp` in place; `docs/testing.md` says so now. If a
companion tombstone ever shows up *without* a preceding in-place overwrite, that is a real bug.

### The method-table swap is one backend for every static BoringSSL (2026-10-26)

`tls/boringssl_table.cpp` replaced `tls/flutter_boringssl.cpp`; the Flutter entry and a new wildcard
entry (`consumer_library = nullptr`, surface `static_boringssl`) share it. Decisions:

- **One original per library, chosen by return address.** Each static BoringSSL has its own
  `session_verify_cert_chain`, and the replacement receives nothing that names the library, but its
  caller (`ssl_verify_peer_cert`) lives in the same one. The backend keeps `{range, original}` per
  hooked library and looks the return address up. A caller outside every range is accepted without
  the original and logged; it should not exist.
- **Wildcard entries skip libraries a named `PATTERN` entry claims**, so `libflutter.so` keeps its
  `flutter` ladder line and nothing is reported twice. Generic rule in the manager, not a special
  case for Flutter.
- **`PatternResult` three-way answer.** `ABSENT` versus `FAILED` matters: OpenSSL builds carry the
  same `"ssl_client"`/`"ssl_server"` strings and no table, and the ladder must say
  `pattern_not_found` for them instead of silence. The host test has a `--absent` fixture
  (OpenVPN3's OpenSSL) for exactly that.
- **`memmem` for the string search.** The first version compared byte by byte; a 40 MB `libapp.so`
  is scanned on every Flutter launch, so the cost had to stay at milliseconds.
- **Which static BoringSSL this does not reach:** users of `SSL_CTX_set_custom_verify` (Cronet; it
  never consults the table, and is reached through its Java verifier instead). The swap still lands
  there, harmlessly, and reports `applied=1`; the coverage docs say so.
- **`is_app_private` became a positive list** (`/data/app/`, `/data/data/`, `/data/user*/`,
  `/mnt/expand/`, `/memfd:`), and wildcard scans skip the library whose load address is this
  module's own (`dladdr`). The first device run reported `static_boringssl present=yes reachable=no
  reason=pattern_not_found` in *every* process: the scan had found the locator's own needle strings
  inside `arm64-v8a.so` under `/data/adb/modules/`, which the old deny-list called app-private. The
  load-address check exists because on Magisk the module is a memfd mapping with no useful name.
- **Chromium libraries are skipped by name** (`skip_consumers` on the wildcard entry:
  `libwebviewchromium.so`, `libmonochrome*`, `libchrome*`, `libcronet.*`, `libtrichrome*`). Their
  BoringSSL has the table (the locator finds it, host-verified on WebView 156) but they verify
  through a custom-verify callback and are reached through their Java verifier; swapping a pointer
  that is never consulted in a 160 MB library every app with a WebView loads is risk for nothing.
- Fixtures: three Flutter engines, WebRTC (`libjingle_peerconnection_so.so`), OpenTok, Brella and
  WebView 156 (packed APS2 + RELR relocations, which the host loader now applies), all located at
  "member 9" of a dozen-pointer table, and the OpenSSL negative. Still at `max`: same primitive as
  before, same owner rule.

### The module hides its own mapping; the host does not hide itself (2026-10-26)

SUPERSEDES, in part, "Hiding our `.so` is the host's job" and the host table's "hidden by host".
Measured on Zygisk Next 1.4.5 (latest is 1.5.2, release notes mention no hiding): in a process where
a module stays loaded, both the module file and `/data/adb/modules/zygisksu/lib64/libzygisk.so`
are mapped by path, and ZN has no setting for it. A generic detector app listed both.

What shipped: `hide/self_remap.cpp`, Magisk Zygisk's `remap_all` idea. After the hooks are
installed, read `/proc/self/maps` once, take every entry whose name is the one containing our own
code (no name assumed: memfd on Magisk, the module file on ZN), copy each into anonymous memory
with the same protection and `mremap(MREMAP_FIXED)` it over the original; PROT_NONE gaps become
anonymous PROT_NONE. Same addresses, so the GOT slots that point into us keep working, and the text
segment replaces itself while executing from it (atomic). `hide.self_remap`, default on, flag in the
`Decision`. Result on device: zero maps entries with our path, `exec_bytes PASS`, all hooks working,
A generic detector app reports only `libzygisk.so`.

Why this is not the `/proc/self/maps`-filtering that §1.9 cut: it modifies only our own mapping, no
libc hook, no text byte of anything else. The one new in-process read is `/proc/self/maps`, which
is not a path of ours. What it does not do: hide the host (not ours to touch), remove a bionic
soinfo entry (ZN loads modules with its own linker, so there is none; the init log says
`loader=host` or `loader=bionic`), or make an anonymous executable region unremarkable. If a future
host loads us through bionic, `dl_iterate_phdr` still names the path; solist removal is the next
step and is Phase 2 material.

### Phase 2 starts with data, and "Dart-side pinning" was mostly Java (2026-10-26)

The plan's Phase 2 is a sketch that says "generate a detailed plan when starting, informed by what
Phase 1 encountered". What Phase 1 encountered: no inline hook exists, so §2.1 (CRC countermeasures)
has nothing to protect and waits; the module hides itself and the host does not (§2.2 done as far
as it can be); nothing needed ArtMethod (§2.5 stays unbuilt). What is left is coverage: foreign
runtimes and whatever real apps on the phone resist. So Phase 2 runs on two inputs: the inventory of
installed apps (pinning plugins, RASP vendor strings, native libraries) and per-app failures.

First finding: the two Flutter pinning packages the plan filed under "Dart-side, compat" do their
comparison in the plugin's *Android* code (`checkConnexion` in `HttpCertificatePinningPlugin` /
`SslPinningPlugin`, fetching the server digest over their own `HttpsURLConnection`). They are plain
DEX targets at `max`, gated by `java_dex`; surface name `dart_pinning` kept, the `libapp.so` marker
reworded for the pure-Dart case that remains. Fixtures in `tests/dex_patcher/fixture/`. Lesson for
the next "foreign runtime" surface: look for the platform-channel plugin first; the Dart side is
often just a messenger.

### Root and tamper hiding moved to a separate module (2026-11-03)

Root and tamper hiding (the `rasp` surface, its Java rows and the root-indicator filter) moved to
rootcheck-haters (https://github.com/morkin1792/rootcheck-haters; module id `rootcheck_haters`,
config at `/data/adb/rootcheck_haters/`); pinning-haters is TLS-only. Both modules install together:
each hooks `adler32` in `libdexfile.so` and they chain through the GOT, verified on the Mi 9T on
2026-11-03.

### Libraries opened by Dart FFI were invisible to the re-scan (2026-11-01)

The deferred-load edge was `android_dlopen_ext` in libnativeloader/libart, i.e. `System.loadLibrary`.
A Flutter plugin that loads its native library from Dart (`DynamicLibrary.open`) goes through
`libflutter.so`'s own `dlopen` import, and so does any SDK loader or plugin host that opens libraries
from native code; such a library was mapped after our snapshot and never evaluated. Two wildcard
rows now hook `dlopen` and `android_dlopen_ext` in every app-private library that imports them (a
handful per app; most import neither). The replacement must not call libdl's wrapper: that wrapper
passes `__builtin_return_address(0)` as the caller, the linker resolves a bare name in the
*caller's* namespace, and our mapping belongs to no namespace — a bare `"libts.so"` would have been
looked up in the default namespace and failed. The hook calls `__loader_dlopen` /
`__loader_android_dlopen_ext` directly with its own return address (the consumer's call site), and
finds those entry points in libdl's import slots rather than through a namespace lookup. Observed in
a Flutter app: `libapp.so (via libapp.so)` in the log is that path firing.


### Static OpenSSL is a second table swap, through exports, not strings (2026-11-01)

The question that produced it: can a surface with no slot to rewrite be reached without a text
patch, since a `.text` patch is primitive #5 and visible to any CRC of that library. For OpenSSL the
answer is yes, by the same move as Flutter: find a const table of function pointers the handshake
consults and swap one member. OpenSSL has no `ssl_crypto_x509_method`, and its chain check
(`ssl_verify_cert_chain` → `X509_verify_cert`) is a direct call; what it does have is the client
`SSL_METHOD`, a struct in `.data.rel.ro` that `TLS_client_method()` returns and whose `ssl_connect`
member every `SSL_connect` / `SSL_do_handshake` goes through. `tls/openssl_table.cpp` swaps that
member for a wrapper that lowers the object's verify mode to `SSL_VERIFY_NONE` (the app's callback
still runs, so this is the wrap again), calls the original, and stores `X509_V_OK` so a
`SSL_get_verify_result` afterwards passes. Decisions:

- **Located through exports, never by heuristic.** `TLS_client_method` is decoded (ADRP+ADD), and the
  decoded address is accepted only if it starts with `TLS_ANY_VERSION` and an option mask of
  `SSL_OP_NO_SSLv3` (1.1.1) or 0 (3.x), with `ssl_connect` and `ssl_accept` both pointing into code.
  `SSL_set_verify`, `SSL_get_verify_callback` and `SSL_set_verify_result` come from the same symbol
  table (`got::find_export`, DT_HASH or DT_GNU_HASH). A build that hides them reports
  `pattern_not_found`, which is the honest answer: the inline alternative is `balanced` and unbuilt.
- **It is `max`**, by the owner's rule from the Flutter entry: a pointer in a data page of an
  app-private library, the same class as the bundled-TLS GOT edges.
- **The BoringSSL backend yields to it.** OpenSSL carries the same `"ssl_client"`/`"ssl_server"`
  strings, so before this the wildcard BoringSSL entry printed `pattern_not_found` for every OpenSSL
  (that was deliberate at the time: better than silence). Now `boringssl_table::install` answers
  `ABSENT` when `openssl_table::is_openssl` says so, and one library gets one ladder line. First
  device run printed both lines on the same library; that is how the rule was found.
- **Verified end to end with a self-built OpenSSL**, because the OpenVPN app on the phone never
  loaded its core without a server. The test app bundles an NDK-built OpenSSL 3.0.16
  (`OPENSSL_DIR`, whole-archived, `-Bsymbolic`, so no slot exists) and handshakes with
  `untrusted-root.badssl.com` under `SSL_VERIFY_PEER`: targeted `verify_result=0`, untargeted
  `verify_result=19`, `exec_bytes` still identical to disk. The OpenVPN3 core is the host fixture.
- **What it does not cover:** an app that inspects the chain itself after the handshake
  (`SSL_get_peer_certificate` plus a digest), per-app rows as ever; and a server-side `SSL_METHOD`
  (irrelevant, apps are clients). Hardware-breakpoint hooking (`perf_event_open`, no text write) is
  the remaining idea for a library with neither slot nor table; a spike, not a plan item.

### Review of everything so far (2026-11-01): what four independent reads found

Four reviewers read the module in parallel (GOT and TLS backends, DEX path, hook manager and the
root filter, companion and WebUI), and every finding was checked against the code before it was
fixed. The ones worth remembering, because each is a rule now:

- **Publish before you swap.** Every slot rewrite (GOT, BoringSSL table, OpenSSL table) used to
  store the original after the pointer went live; any thread calling through it in between ran a
  replacement with a null original. `try_hook` reads the slot and stores the original first, and
  the table backends publish their `{range, slot, original}` entry before `hook_slot`. Dispatch by
  return address walks entries newest first, and an entry whose slot no longer holds our function
  belongs to an unloaded library and is ignored (same for `got::Record`).
- **A struct layout comes from the version, never from the table.** OpenSSL 3.2 inserted four
  members ahead of `ssl_connect`; at +48 there is still a code pointer (`ssl_clear`), so every
  plausibility check passed and the ladder said `applied`. The layout is chosen from the version
  text, and the host suite has a 3.4.1 fixture next to 3.0.16 and the OpenVPN core.
- **Identify our own mapping by file identity.** Magisk's module memfd is named `jit-cache`, the
  same as ART's JIT code cache; matching by name alone would have replaced the JIT cache's shared
  views. `self_remap` matches device and inode, and runs before the hooks so no thread writes our
  data while it is copied.
- **Root never walks app-writable directories as root.** The secondary-DEX walk runs with the
  directory owner's fsuid; measured on device: a root-owned directory planted in the app's data dir
  keeps its file, an app-owned one is cleaned.
- **Touch only what you patch, and put it back as it was.** The DEX path now checks for a target
  before changing protection, insists on one private mapping, and restores the protection it found.
- **Never wait unboundedly on our lock from a dlopen hook.** The linker's lock may be held by the
  waiting thread; the rescan is handed to the lock holder after 200 ms.
- Left as they are, on purpose: the libdl fallback in the app `dlopen` hook (reached only if the
  linker entry is missing), execute-only segments (not enforced for app libraries on current Android), adopted storage
  (documented in known-limitations).

### No app-specific bypasses in the module (owner decision, 2026-11-03)

The module ships generic surfaces: TLS libraries, platform trust, SDKs and frameworks many apps
share. Rows that only make sense for one app (its obfuscated class names, its own tamper
callbacks) are not added. Diagnosing an app is fine and is what the tools and this file are for;
the patch that follows from it stays out of the table. Applied the same day: the build-specific
rows from the Kony banking app work (its network-library probes, Topaz Heartbeat's R8-letter wrappers and
`getInfo` checks, the Kony exit dispatcher) were removed with the `NOP_CALLS` kind only they used.
SDK- and framework-level rows that are name-stable across apps stay. Root and tamper hiding moved to
rootcheck-haters (https://github.com/morkin1792/rootcheck-haters) the same day.

### The deferred-load edge is libdl.so's own linker slots, not the importers' (2026-11-03)

SUPERSEDES "Libraries opened by Dart FFI were invisible to the re-scan (2026-11-01)" and the
libnativeloader/libart part of "The deferred-load edge is in `libnativeloader.so`, not `libart.so`".

A React Native app carrying a protection SDK died with `SIGSEGV` at address 0 on its
`create_react_context` thread two seconds into every targeted launch, and lived untargeted. It died
with every surface off, with the stat fallback off, and with oat eviction off; the only in-process
writes left were the deferred-load rows. A build without the two app-private `dlopen` rows ran it
with every surface applied. The SDK's libraries import `dlopen`, were hooked like any other
app-private importer, and the SDK verifies its own `.got.plt` against `.rela.plt` (the strings are in
its guard library); a slot pointing outside `libdl.so` is its tamper signal. The reaction is
deliberate (a null call; under strace, after a double fork, one of the app's own threads ended the
process with `kill(getpid(), SIGKILL)`), so there is never a tombstone to read.

The replacement is the question the detection model asks first: the lowest-numbered primitive that
reaches "every library load". `dlopen` and `android_dlopen_ext` are thin wrappers in `libdl.so`
that call the linker's `__loader_dlopen` / `__loader_android_dlopen_ext` through libdl's own import
slots, passing `__builtin_return_address(0)` for namespace resolution. Two `R_AARCH64_JUMP_SLOT`
rewrites in one system library (primitive #3) see every load in the process — `System.loadLibrary`
through libnativeloader, Dart FFI through `libflutter.so`, SDK loaders, packers, libc — where the
old design needed GOT writes in `libnativeloader.so`, `libart.so` and every app-private importer
(primitive #4, in the libraries most likely to check). The replacement forwards the caller address
untouched, so the `__loader_*`-with-caller trick from the superseded entry is no longer needed.
Contract C3 now reads `libdl.so` (the extractor pulls it from the runtime APEX).

Rule that falls out of it: **a GOT write in an app-private library is reserved for surfaces that
exist only there** (a bundled `libssl` consumer, a static TLS table). Anything process-wide — loading,
file access, properties — has a system-library slot somewhere on the path; find it. Protection SDKs
check the GOTs they own, not bionic's.
