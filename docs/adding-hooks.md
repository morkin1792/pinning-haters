# Adding hooks

Hooks are data. Adding a pinning surface means appending an entry to `kJavaTargets`
(`module/jni/hooks/targets_java.cpp`) or `kNativeTargets` (`module/jni/hooks/targets_native.cpp`).
It must not require per-target logic in `hook_manager.cpp` or `dex_intercept.cpp`. If a target needs
behaviour the tables cannot express, extend the struct in `hooks/targets.h` with a new field, and
make the manager honour it generically.

Two fields are mandatory on every entry and are not optional in review:

- `min_tier`: the quietest tier at which the entry may be installed. Everything shipping today is
  `Tier::MAX`; an entry that needs an inline or pattern hook is `Tier::BALANCED`.
- `surface`: a `SurfaceId`. A target without one is invisible to the coverage ladder, which makes it
  undebuggable in the field.

## Before adding a Java target: which side of the handshake does it run on?

Ask: **is this method invoked as a `TrustManager` (or from one) during the TLS handshake?** If yes,
the conscrypt `custom_verify` wrap already reaches it, more cheaply and in places DEX patching cannot
go, and the Java entry is dead weight. That covers platform trust, Network Security Config pins,
TrustKit, Volley, gRPC-over-OkHttp and any custom `X509TrustManager`.

Only pinning that runs **after** a successful handshake, by reading the negotiated chain, belongs in
the Java table. OkHttp `CertificatePinner` is the canonical case. Other candidates: Certificate
Transparency interceptors implemented as OkHttp interceptors, app-specific
`getPeerCertificates()` digest comparisons, `WebViewClient.onReceivedSslError` overrides.

Two more exclusions:

- **Bootclasspath classes** (`com.android.org.conscrypt.*`, `android.security.net.config.*`,
  `android.net.http.*`, the platform's `org.apache.http.legacy`) are preloaded in zygote and
  AOT-compiled into the boot image. There is no app-owned DEX to patch. They cannot be Java targets.
- **Interface methods** (`javax.net.ssl.X509TrustManager.checkServerTrusted`,
  `javax.net.ssl.HostnameVerifier.verify`) have no bytecode. Target the implementing class instead.

Hostname verification is not pinning. Entries for hostname verifiers go under
`SurfaceId::HOSTNAME_VERIFIER`, which the manager gates behind `relax_hostname_verification`.

## `JavaTarget`

```cpp
struct JavaTarget {
  const char* class_descriptor;  // "Lokhttp3/CertificatePinner;"  (DEX descriptor, L...; form)
  const char* method_name;       // "check"  (exact, including Kotlin suffixes like "check$okhttp")
  const char* method_signature;  // "(Ljava/lang/String;Ljava/util/List;)V"  (DEX method descriptor)
  ReplacementKind replacement;   // RETURN_VOID | RETURN_TRUE | RETURN_FALSE | INTERCEPTOR_PROCEED | RETURN_NEW_INSTANCE | CHROMIUM_TRUST_LEAF
  Tier min_tier;                 // Tier::MAX for DEX patches
  SurfaceId surface;             // coverage ladder
  const char* label;             // "okhttp3.CertificatePinner.check(String, List) 3.x-5.x"
};
```

- The class must be **defined** in the DEX, not just referenced. A class referenced here but
  defined in another DEX reports `CLASS_ABSENT` for this DEX and is picked up when that DEX is
  verified.
- Each overload is its own entry. The signature is matched exactly against the proto; a mismatch is
  `METHOD_ABSENT`, which is normal across library versions and is logged at `DEBUG`.
- Every kind also relocates the method's `try` ranges onto the nop tail and repoints handler
  addresses that fell inside the template (`relocate_tries`); `too_small` can therefore also mean
  `insns_size < template + tries_size`. Nothing changes size.
- `CHROMIUM_TRUST_LEAF` is specific to `AndroidNetworkLibrary.verifyServerCertificates`: it calls
  `addTestRootCertificate(certChain[0])` on the same class and then the one other *static* method in
  the DEX with the same signature (the R8-renamed `X509Util` verifier, found by
  `find_static_method_by_proto`). Scratch is v0 when the method has a free local; on the
  5-argument form the last parameter (`sctList`, nullable) doubles as scratch when R8 left no locals,
  which is what the real WebView build looks like. Needs `outs_size >= ins_size`. `no_callee` means
  either method is missing, `no_registers` that neither scratch option applies.
- `RETURN_NEW_INSTANCE` returns a freshly constructed object: set `aux_type` to the class descriptor
  and `aux_ctor` to `"()V"` or `"(I)V"` (the int is always 0). The type and `<init>` ids are resolved
  from the DEX being patched; `no_callee` means it does not reference them. 6 or 7 code units,
  needs `outs_size >= 2` for the int form. Chromium's `AndroidCertVerifyResult(0)` is the first user.
- `INTERCEPTOR_PROCEED` is for `okhttp3.Interceptor.intercept(Chain)` bodies only. It rewrites the
  method to `return chain.proceed(chain.request())`: 11 code units using `/range` invokes so any
  register number works, with the two `Interceptor$Chain` method ids resolved from the DEX being
  patched (`dex::View::find_method`). Needs `registers_size >= 2`, `ins_size >= 2` and
  `outs_size >= 2` (every real interceptor calls `proceed`, so the verifier's outs check holds);
  `no_callee` means the DEX never references the Chain methods. Use it for any library whose
  pinning or CT check lives in an interceptor.
- `RETURN_TRUE`/`RETURN_FALSE` need at least one register (`registers_size >= 1`),
  which every real method has. `RETURN_FIRST_ARG` is **not implemented**: its former consumers were
  all bootclasspath targets that were removed. If a future target needs it, `p0` is `this` for
  instance methods, the first explicit argument is `p1`, and the register number is
  `registers_size - ins_size`; unit-test it on the host before shipping.
- The patcher writes the template over the first code units and nop-fills to `insns_size`. It never
  changes `insns_size`, `tries` or `handlers`. Abstract and native methods are `NO_CODE`.
- The `label` appears in `DEBUG` lines; make it name the library and version range.

### Test expectations for a Java target

`tests/dex_patcher/test_dex_patcher.cpp` runs the **production table** against a d8-built fixture
(`tests/dex_patcher/fixture/`) and asserts exact counts: every `OKHTTP_PINNER` entry patches
(`okhttp_ok == 4`), both `okhttp3/internal/tls` entries patch (`hostname_ok == 2`), and the Apache
entries are absent (`apache_absent == 4`). Adding an entry changes those numbers, so:

1. Add a shape-compatible stand-in class to `tests/dex_patcher/fixture/` with the exact descriptor,
   name and signature. Give the body try/catch, a `switch` (payload data inside `insns[]`) and
   4-byte instructions if the real method has them, so nop-fill and the untouched-tries rule are
   exercised (`okhttp3/CertificatePinner.java` is the model).
2. Update the count assertions in section 1 of the test; the byte checks in section 2 apply to every
   present target automatically.
3. Run `tests/run_host_tests.sh`. It builds the fixture, runs `test_dex_patcher`, `test_got`,
   `test_config`, and then **re-dexes the patched DEX with d8**, which parses every instruction of
   every method and fails on a broken nop-fill or a try/handler address off an instruction boundary.

Requirements: `javac`, and `d8` found through `D8`, `R8_JAR` or `ANDROID_HOME`.

## `NativeTarget`

```cpp
struct NativeTarget {
  const char* provider_library;  // where the symbol is defined; informational for GOT style
  const char* symbol;            // the imported function name, as in .rela.plt
  const char* consumer_library;  // whose GOT slot is rewritten (see below)
  void*       replacement;       // our function, same signature as the original
  void**      original;          // where the manager stores the original pointer; may be nullptr
  HookStyle   style;             // GOT_IN_CONSUMER | INLINE_IN_PROVIDER | PATTERN
  Tier        min_tier;
  SurfaceId   surface;
  const char* label;
};
```

- `consumer_library` is either a **`|`-separated candidate list** (`"libartbase.so|libart.so|libdexfile.so"`)
  or **`nullptr`**. A candidate list is how per-Android-version library moves are absorbed without
  code: every candidate that is loaded *and* has the edge is hooked, and a loaded candidate without
  the edge reports `contract_missing`. There is no separate `art_contracts.cpp`; the candidate list
  *is* the per-version table. `nullptr` means "every app-private library that imports the symbol",
  now and after each deferred load; it is the right choice for bundled-TLS symbols where the calling
  library is whatever the app shipped.
- `replacement` must have the original's exact signature. Write it in `tls/tls_hooks.h` /
  `tls/bundled_tls.cpp` (or a sibling), keep every library-owned object opaque (`void*`), and call
  through `*original` when the original behaviour is needed. Replacement functions run on the app's
  threads; no allocation-heavy work, no exceptions, no new threads.
- `original` is shared across every consumer library that is hooked for this entry. If two loaded
  libraries resolve the symbol to **different providers** (two bundled BoringSSL copies), the manager
  hooks the first and skips the second with a `WARN`, because calling provider A with provider B's
  objects would be an ABI mismatch.
- `style`: `GOT_IN_CONSUMER` is the primary backend. `PATTERN` entries work when they carry a
  `pattern` backend: `PatternResult (*)(const got::Library&)` that locates and rewrites a pointer slot
  inside one library and answers `ABSENT` (nothing of the kind here), `APPLIED`, or `FAILED` (present,
  slot not pinned; the ladder prints `reason=pattern_not_found`). The write must go through
  `got::hook_slot`, so it is idempotent, RELRO-aware and restorable, and it must be a data pointer,
  never code. The backend owns its replacement and its per-library originals (dispatch by return
  address when several libraries carry the same table), so `replacement` and `original` stay
  `nullptr` on these entries. `tls/boringssl_table.cpp` is the model; `tls/openssl_table.cpp` is the
  second instance (the OpenSSL `SSL_METHOD` table, found through exports instead of strings). When
  two wildcard backends could claim the same library, the one that does not own it answers `ABSENT`
  (the BoringSSL backend yields to `openssl_table::is_openssl`), so one library gets one line. A `PATTERN` entry with
  `consumer_library = nullptr` runs on every app-private library except those another `PATTERN` entry
  names explicitly: that is how `libflutter.so` reports as `flutter` while everything else reports as
  `static_boringssl` or `static_openssl` from the backend that recognises it. `INLINE_IN_PROVIDER` entries, and `PATTERN` entries without a
  backend, are still legal and useful: they make the ladder report `reason=backend_unavailable` with
  the tier instead of saying nothing.
- The quietest-primitive question comes first: **what is the lowest-numbered primitive that reaches
  this surface?** Look for a cross-library call before reaching for an inline hook. The conscrypt
  wrap and the `adler32` interception were both found that way, and both replaced louder designs.

### Adding a system-library edge

An entry whose consumer is an ART or conscrypt library is a dependency on another project's build
configuration. It needs:

1. a verification row in `docs/android-versions.md` for every supported API level;
2. an assertion in `tools/check_elf_contracts.sh`, so a new Android release that drops the import
   fails CI rather than failing on a user's device;
3. a `balanced` fallback entry in the table if the edge is likely to move (the table keeps
   `OpenCommon` in mind for the DEX path for exactly this reason).

### Symbol candidates for inline fallbacks

Where a mangled ART symbol is needed (future `INLINE_IN_PROVIDER` entries), use a candidate list, not
one name, and copy candidates with attribution from projects that ship against real devices: LSPlant,
Vector, LSPatch, Pine, SandHook, in that order. None of them carry `DexFile`/`DexFileLoader`
candidates, which is part of why the DEX path uses the `adler32` edge and needs no ART symbol. Verify
anything from a blog post or a Stack Overflow answer with `nm -D` before shipping.

## `RuntimeMarker`

```cpp
struct RuntimeMarker {
  const char* library;   // basename; a trailing '*' matches a prefix ("libcronet.*")
  SurfaceId   surface;
  Tier        required_tier;
  const char* note;      // one sentence, shown in the coverage line
};
```

Presence-only. Costs a string compare over loaded library names, never a hook. Add one whenever a
runtime exists that the tables cannot reach at some tier, so the user sees `required_tier` instead
of silence.

A marker can also be a **string** instead of a library name (`needle` field): Go's `crypto/tls`
and rustls live in libraries named after the app, so `kRuntimeMarkers` carries the string each
stack always embeds (`"crypto/tls: "`, `"/rustls-"`) and the manager reports every app-private
library whose readable segments contain it (`got::segments_contain`, memmem, milliseconds for a
40 MB library). Pick a needle the stack cannot ship without; a crate path or an error prefix is
better than a word.

## Adding a `SurfaceId`

1. Add the enumerator to `SurfaceId` in `hooks/targets.h`, before `COUNT`, with a comment.
2. Add its name to `surface_name()` in `hooks/hook_manager.cpp`. Names are `snake_case` and appear
   verbatim in log lines and docs.
3. Map it to a config group in `surface_bit()` in the same file (`platform_tls`, `java_dex`,
   `bundled_tls`, `foreign_runtime`), or return 0 for a mechanism the user should not be able to
   switch off.
4. Decide whether it is reported per DEX (add it to the exclusion in the `present=no` summary loop)
   or once at install.
5. Add a row to the surface table in `docs/coverage.md`. This is not optional.

## Documentation that changes with a hook

| Change | Update |
|---|---|
| New target entry | `docs/coverage.md` if its surface row changes; `CHANGELOG.md` |
| New `SurfaceId` | `docs/coverage.md` surface table; `docs/adding-hooks.md` if the workflow changed |
| New system-library edge | `docs/android-versions.md`; `tools/check_elf_contracts.sh` |
| New tier-gated capability | `docs/stealth-tiers.md` |
| Config schema change | `examples/config.example.json`, `docs/reference.md` config reference, `tests/host/test_config.cpp` |
| New Android version | `docs/android-versions.md` |

Out-of-date documentation in a security tool misleads users. Docs ship with the code change, in the
same PR.

## Style

C++20, no exceptions in hook paths, no global mutable state outside the explicit singletons, no
threads in the target process, `snake_case` files and functions, `PascalCase` types,
`SCREAMING_SNAKE` constants, named constants for every DEX opcode (`dex/dex_format.h`), a GPL-3
header on every new file, and comments that explain *why*, especially anywhere a future reader might
be tempted to simplify the `adler32` trick or the wrap-not-replace choice.
