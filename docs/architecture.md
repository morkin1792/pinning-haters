# Architecture

How a launch of a targeted app flows through the module, which component owns what, and why the
pieces are coupled the way they are. The reasoning behind each decision is in `AGENTS.md`; this
document describes the code as it is.

## Process view

```
zygote (Zygisk host)                          Zygisk daemon (root)
┌───────────────────────────────┐             ┌──────────────────────────────┐
│ preAppSpecialize              │  Request    │ companion_main               │
│   build Request from args     │ ──────────▶ │   re-read config.json        │
│   connectCompanion()          │             │   decide(package) → Decision │
│                               │  Decision   │   read api_level / build     │
│   not a target → unload       │ ◀────────── │   evict oat artifacts        │
│   target → pipe(), send read  │             │   log.enabled? recv pipe fd, │
├───────────────────────────────┤             │     rotate, open log file,   │
│ postAppSpecialize (app UID)   │  log records│     serve_log() until EOF    │
│   art::init, log::init        │ ──────────▶ │   else close                 │
│   hooks::install(Decision)    │             └──────────────────────────────┘
│   (Zygisk socket closed in pre)│
└───────────────────────────────┘
```

1. **`preAppSpecialize`** (`module.cpp`). Still zygote-privileged but we read nothing from disk here.
   The module builds an `ipc::Request` from the Zygisk args: `uid`, `nice_name` (log only), the
   `app_data_dir`, and the package name, which is the basename of the data dir (reliable even for
   `android:process` processes). It connects to the companion, sends the request, reads an
   `ipc::Decision`. If the companion is unreachable, the magic is wrong, or `target == 0`, the
   module sets `DLCLOSE_MODULE_LIBRARY` and returns: nothing else happens in that process.
   Otherwise the socket is exempted from Zygisk's fd sanitation and kept.
2. **`companion_main`** (`companion.cpp`), running as root in the Zygisk daemon, one invocation per
   connecting process. Re-reads `/data/adb/pinning_haters/config.json` on every request (small
   file, no cache, no stale state), resolves the per-package tier, reads `ro.build.version.sdk`,
   `ro.product.manufacturer`, `ro.build.version.release` and `ro.build.version.security_patch` so
   the app process never reads a property, performs oat eviction if the package is a target and
   `aot.evict_oat` is on, and replies. If `log.enabled` is set, the module then creates a pipe and
   sends its read end over the Zygisk socket with `SCM_RIGHTS`; the companion rotates the log
   directory, opens `<package>-<timestamp>.log`, and streams log records from the pipe into it until
   the app exits. The Zygisk socket is closed by both sides at this point: it was created inside the
   app process while that process still carried zygote's SELinux label, and after specialization the
   app domain may not write to a zygote-labelled socket (verified on device: `avc: denied { write }
   ... tcontext=u:r:zygote:s0 tclass=unix_stream_socket`). The reverse hand-over, a socket created
   by the companion, is blocked too: the zygote-labelled process may not receive a magisk-labelled
   socket. A pipe created by the zygote-labelled process stays writable from the app domain, which
   is why the app creates the channel.
3. **`postAppSpecialize`**, now running as the app's UID. Caches the `JavaVM`, initialises the log
   sink with the pipe's write end (or nothing, when logging is off: the process then holds no
   descriptor of ours), and calls `hooks::install(decision)`. With logging on the pipe stays open
   for the process lifetime so class-load-time DEX patches and deferred library loads can still
   report. `DLCLOSE_MODULE_LIBRARY` is never set for a target: our replacement functions live in the
   library.
4. **`preServerSpecialize`** always unloads. The module is never present in `system_server`.

The wire format (`ipc.h`) is two fixed-size structs with a magic/version check. Both ends are the
same `.so` built from the same tree, so there is no further versioning.

| `Request` | `Decision` |
|---|---|
| `magic`, `version`, `uid` | `magic`, `target` |
| `package[256]` (basename of data dir) | `tier` (effective: global ceiling or per-package override) |
| `process[256]` (nice name, log only) | `surfaces` (bitmask: platform_tls 0x01, java_dex 0x02, bundled_tls 0x04, foreign_runtime 0x08) |
| `data_dir[256]` (for secondary-dex oat dirs) | `flags` (relax_hostname 0x01, log_enabled 0x02, log_verbose 0x04, stat_fallback 0x08) |
| | `api_level`, `evicted` (artifacts deleted), `build[96]` (`manufacturer/release/patch`) |

After the decision, while the socket is open, the app side sends `LogHeader{length, level}` followed
by the text; the companion adds the timestamp.

## Components

| Path | Role |
|---|---|
| `module/jni/module.cpp` | Zygisk entry, lifecycle, companion handshake. Registers both the module and the companion. |
| `module/jni/companion.cpp` | Root side: config, decision, oat eviction, log files, rotation. |
| `module/jni/config/` | Config parser (nlohmann/json, companion-side only; the only code built with exceptions) and `decide()`. |
| `module/jni/ipc.h` | Wire structs, `Tier`, surface and flag bits, `read_all`/`write_all`. |
| `module/jni/log/` | App-side log sink: formats on the calling thread, one `write()` per record down the pipe (≤ PIPE_BUF, POLLERR-checked). No threads. |
| `module/jni/got/` | GOT/PLT rewriter over `.rela.plt`: `find_library`, `find_slot`, `has_edge`, `hook`, `hook_in`, `restore`. |
| `module/jni/hooks/targets.h` | `SurfaceId`, `JavaTarget`, `NativeTarget`, `RuntimeMarker`. Hooks are data. |
| `module/jni/hooks/targets_java.cpp` | Category A table: methods patched in DEX. |
| `module/jni/hooks/targets_native.cpp` | ART contracts, platform TLS, bundled TLS, pattern entries, runtime markers. |
| `module/jni/hooks/hook_manager.cpp` | Tier gate, style selection, presence detection, coverage lines, deferred loads. No per-target logic. |
| `module/jni/dex/dex_format.h` | DEX structs and named opcode constants. |
| `module/jni/dex/dex_parser.cpp` | Bounds-checked read-only `View` over an unverified DEX (035 to 041). |
| `module/jni/dex/dex_patcher.cpp` | Pure bytes-to-bytes patch of a code item. Host-testable. |
| `module/jni/dex/dex_intercept.cpp` | The `adler32` replacement: checksum, patch, return saved value. |
| `module/jni/tls/conscrypt_wrap.cpp` | Platform TLS: wrap of conscrypt's verify callback. |
| `module/jni/tls/bundled_tls.cpp` | App-bundled BoringSSL/OpenSSL replacements. |
| `module/jni/art/aot_fallback.cpp` | `stat`/`open`/`access` replacements hiding oat artifacts. |
| `module/jni/art/art_api.cpp` | Cached `JavaVM`, `JNIEnv` for the current thread. |
| `module/jni/zygisk.hpp` | Zygisk API v4 header. |
| `module/jni/exports.map` | Only `zygisk_module_entry` and `zygisk_companion_entry` are exported. |

Build flags that matter: `-fvisibility=hidden -fno-exceptions -fno-rtti` on everything except
`companion.cpp` and `config.cpp`; full RELRO and `-z now`; `--build-id=none`; arm64-v8a only.

## Hook installation (`hooks::install`)

1. Log the `[init]` line: version, `api`, `build`, `tier`, `surfaces`, `flags`, `oat_evicted`.
2. Snapshot the loaded libraries once via `dl_iterate_phdr` (read, never hooked). Hooking inside the
   iteration callback would nest the linker's lock, hence the snapshot.
3. Walk `kNativeTargets` in table order. For each entry:
   - If the entry is blocked (tier ceiling, surface toggle, or `aot.stat_hook_fallback`) or its
     style has no backend, do presence detection only: is a candidate consumer (or, for pattern
     entries, the provider) loaded?
   - Otherwise, for every loaded library matching `consumer_library` (a `|`-separated candidate
     list, or every app-private library when `nullptr`), rewrite the import slot and record the
     original pointer. Every candidate that has the edge is hooked.
   - Emit one coverage line (format in `docs/coverage.md`).
4. Walk `kRuntimeMarkers`: a string compare of loaded library basenames (a trailing `*` matches a
   prefix) that emits `present=yes reachable=no required_tier=...` for runtimes nothing reaches at
   the current tier.
5. Emit `present=no` once for every surface that never appeared, except the per-DEX surfaces
   (`okhttp_pinner`, `hostname_verifier`), which are reported when a DEX is verified.

Java targets are *not* installed here. They are applied lazily, whenever ART verifies a DEX that
defines the target class, through the interception below.

## The three GOT edges and their relatives

All default-tier native work is a GOT slot rewrite in a **system** library (ranking primitive 3) or
in the app's own libraries for bundled TLS (primitive 4). The rewriter parses only `.rela.plt`:
imported functions get `R_AARCH64_JUMP_SLOT` entries there, and `.rela.plt` is never subject to
Android's packed relocation encoding (only `.rela.dyn` is), which is why it is ~150 lines. For each
write it `mprotect`s the page RW, exchanges the pointer atomically, and restores the protection the
segment is supposed to have (RELRO wins over the `PT_LOAD` flags). Slots are recorded so that a
re-scan after a deferred load hands back the real original instead of stacking.

| Edge | Consumer (slot rewritten) | Provider | Purpose |
|---|---|---|---|
| `SSL_set_custom_verify` (and `SSL_CTX_set_custom_verify`, when imported) | `libjavacrypto.so` | conscrypt APEX `libssl.so` | platform TLS wrap |
| `adler32` | `libdexfile.so` | `libz.so` | DEX patch at verification |
| `__loader_dlopen`, `__loader_android_dlopen_ext` | `libdl.so` | the linker (`ld-android.so`) | deferred loads |
| `stat`, `fstatat`, `open`, `__open_2`, `openat`, `access` | `libartbase.so`, `libart.so`, `libdexfile.so` | `libc.so` | oat-artifact hiding fallback (API 34 imports: `stat`, `open`, `__open_2`, `access`; the rest are candidates) |
| `SSL_CTX_set_verify`, `SSL_set_verify`, `SSL_CTX_set_custom_verify`, `SSL_set_custom_verify`, `SSL_CTX_set_cert_verify_callback`, `SSL_get_verify_result` | every app-private library importing them | the app's `libssl.so` | bundled TLS |
| `X509_verify_cert` | every app-private library importing it (typically the app's `libssl.so`) | the app's `libcrypto.so` | bundled TLS |

The stat/open/access family is a candidate list: on a given Android version only some members are
imported by some of the three libraries (on API 34, `open` and `stat` in `libartbase.so`;
`access`, `open`, `stat` in `libart.so`). Every member that exists is hooked; the ones that do not
exist produce a `contract_missing` coverage line, which is expected for that surface.

### Platform TLS: wrap, do not replace

`libjavacrypto.so` calls `SSL_set_custom_verify(ssl, mode, cert_verify_callback)` for each
connection. Our replacement remembers conscrypt's callback and passes `wrapped_verify` instead.
`wrapped_verify` calls conscrypt's callback first; that is what runs `SSLHandshakeCallbacks.verifyCertificateChain`
and, through it, the platform or app `TrustManager`. If the verdict is `ssl_verify_ok` or
`ssl_verify_retry` it is returned untouched. If it is `ssl_verify_invalid`, the `TrustManager` has
thrown and the `CertificateException` is pending on the current Java thread; the wrap clears it via
`JNIEnv::ExceptionClear()` and returns `ssl_verify_ok`. Replacing the callback would be one line
simpler and strictly louder: the app's `TrustManager` would never be constructed or called, and "was
my trust manager invoked" is a check an app can make without hunting for hooks.

### DEX patching at verification time

`DexFileVerifier::CheckHeader` computes the Adler-32 of everything after the 12-byte
magic+checksum prefix by calling zlib's `adler32`. Our replacement:

1. passes through the `Z_NULL` seed call and anything whose `buf - 12` does not start with `dex\n`;
2. calls the original `adler32` **first** and keeps the result: the checksum of the unpatched bytes;
3. opens a bounds-checked `View` over the DEX (`buf - 12`, `len + 12`; for DEX 041 the view is
   re-based to the container), `mprotect`s the pages RW, and for every `JavaTarget` whose class is
   defined in this DEX either patches the method or records why it was blocked;
4. restores `PROT_READ`, emits one coverage line per surface present in this DEX, and returns the
   **saved** checksum.

The verifier compares that value with the untouched header field, they match, and verification
proceeds over the patched bytes. The header checksum is never rewritten, so the in-memory header
still matches the APK. A small table remembers `(base, size) → checksum` for the DEX files patched so
far, so a later re-checksum of the same mapping (`DexFile::CalculateChecksum`, `OatFileAssistant`)
keeps seeing the header's value.

The patch itself (`patch_code_item`) writes the replacement template over the first one or two code
units and fills the rest of `insns[]` with `nop`. It never changes `insns_size`, `tries` or
`handlers`, so the code item stays structurally identical. Templates:

```
RETURN_VOID   0E 00          return-void
RETURN_TRUE   12 10  0F 00   const/4 v0, 1 ; return v0
RETURN_FALSE  12 00  0F 00   const/4 v0, 0 ; return v0
```

The nop-fill is a correctness requirement, not tidiness: the verifier sweeps every code unit up to
`insns_size`, so a 2-byte `return-void` landing on the first half of a former 4-byte instruction
would leave garbage for the sweep and the class would be rejected. There is no `madvise`: the mapping
is `MAP_PRIVATE` (file-backed, or anonymous for an extracted entry) and `MADV_DONTNEED` would zero
an anonymous page.

The mapping is `MAP_PRIVATE`, so the write copies on write and touches neither the file nor any
other process. `mprotect` failures, unparseable DEX files, abstract and native methods, methods with
too few code units or registers, and malformed structures are all logged and skipped; nothing is a
hard failure.

### Why oat eviction is coupled to the DEX path

ART runs AOT-compiled code from the package's `.odex` when it has it, and skips `DexFileVerifier`
entirely when a `.vdex` supplies `VerifierDeps`. Either one makes the DEX bytes irrelevant or the
interception silent. So the companion **deletes** (not `pm compile --reset`, not a `verify`-filter
recompile, both of which leave a vdex) every `.odex`, `.vdex` and `.art` it finds under
`/data/app/*/<pkg>-*/oat/*/` and under the app's data directory (secondary DEX, walked with a cap of
20000 entries). ART then runs the APK's DEX under interpreter plus JIT for that launch. The
in-process fallback, when enabled, makes any surviving artifact under `/data/.../oat/...` look absent
to ART's own `stat`/`open`/`access` calls by returning `ENOENT`; nothing outside `/data` is ever
hidden, so boot-image files are untouched.

### Deferred loads

`dlopen` and `android_dlopen_ext` are thin wrappers in `libdl.so`: each calls the linker's
`__loader_dlopen` / `__loader_android_dlopen_ext` through libdl's own import slot, passing its
caller's return address for namespace resolution. Those two slots are the edge. Every load in the
process passes through them — `System.loadLibrary` (libnativeloader), Dart FFI's
`DynamicLibrary.open` in `libflutter.so`, SDK loaders, packers, libc — so two writes in one system
library cover them all. The replacement forwards the caller address untouched, and after the
original returns a handle re-runs the native table against the libraries that are newly mapped
(the named one and its `DT_NEEDED` chain) and re-checks the runtime markers, on the calling thread.

An earlier design rewrote `android_dlopen_ext` in `libnativeloader.so` / `libart.so` and `dlopen`
in every app-private library that imported it. The second part wrote into protection SDKs' own
libraries, and those verify their `.got.plt` against `.rela.plt`: one of them killed the app with a
null-pointer `SIGSEGV` two seconds into launch. The libdl slots reach strictly more loads with
strictly fewer, quieter writes (2026-11-03).

## What is deliberately absent

- No threads are created in the target process. Log records go out on the calling thread.
- No files are opened, created or stat'ed by the module in the target process. The companion does
  all file work.
- No RWX pages. GOT pages are RW only for the duration of one atomic store.
- No `INLINE_IN_PROVIDER` or `PATTERN` backend. shadowhook is not vendored in v0.1.0; those entries
  stay in the table so the coverage ladder can name the tier that would reach them.
- No `/proc/self/maps` filtering, no `dl_iterate_phdr` hooking, no property spoofing. See
  `docs/detection-model.md`.
