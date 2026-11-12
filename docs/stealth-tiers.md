# Stealth tiers

pinning-haters wants to be close to universal *and* as undetectable as possible. For a minority of
surfaces those pull in opposite directions. Rather than a global compromise that makes every user pay
the detection cost of the hardest app they have, there are three tiers, a global ceiling, and a
per-package override.

## Definitions

| Tier | Primitives permitted (numbers from `docs/detection-model.md`) | Status in v0.1.0 |
|---|---|---|
| `max` (default) | 1 DEX patch, 2 companion-side file operations, 3 GOT in system libraries, 4 GOT-class pointer writes in app-private libraries only for bundled TLS (import slots, and the BoringSSL method table of `libflutter.so` or any other statically linked BoringSSL) | implemented |
| `balanced` | `max` + 5 inline `.text` hooks in system and app libraries | no backend yet; no table entry needs one today (Flutter turned out to be reachable without it) |
| `compat` | `balanced` + 7 ArtMethod entry-point hooks + 6 libc-level hooks + foreign-runtime metadata patching | nothing yet (Phase 2) |

## What each tier reaches

| | `max` | `balanced` | `compat` |
|---|---|---|---|
| **Reaches** | everything validated through a `javax.net.ssl` `TrustManager` (platform trust, Network Security Config pin-sets, TrustKit, custom `X509TrustManager`s, Volley, gRPC-over-OkHttp); OkHttp `CertificatePinner`; app-bundled BoringSSL/OpenSSL whose calling library imports the verify symbols; Flutter's internal BoringSSL (method-table swap); WebView/Cronet chain verification (Chromium's Java verifier, DEX patch) | + statically linked BoringSSL whose chain check does not go through the method table (custom-verify users), + OpenSSL linked statically, + any library with no usable GOT edge | + methods ART compiled before our window, + bootclasspath methods, + Unity IL2CPP, + Mono/Xamarin, + Go crypto/tls and rustls, + Dart-side pin packages, + Cronet pin APIs |
| **New detection exposure** | GOT snapshot diff; in-memory DEX vs APK DEX; absent oat artifacts | + text CRC of each inline-hooked library | + the standard Xposed entry-point checks; + libc CRC |
| **Needs CRC countermeasures** | no | yes | yes |

The important property of `max`: there is nothing for a text-CRC check to find, so the whole
CRC-defeat problem is confined to the higher tiers.

## Configuration

```json
{
  "stealth": "max",
  "packages": {
    "com.example.targetapp": {},
    "com.example.hardened": { "stealth": "balanced" }
  }
}
```

- `stealth` is the **global ceiling**. It applies to every package that does not override it.
- `packages.<pkg>.stealth` **replaces** the ceiling for that package only. It can raise it (the
  usual case: one hardened app whose surface needs an inline hook) or lower it (a package you want kept at `max`
  while experimenting globally). Everything else stays at the global value.
- There is no way to set a tier for all apps at once that is louder than `max` except by changing
  the global value, and `docs/reference.md` warns against that. Escalate the one app that needs it.

Mechanically, the tier is a **filter over a data table**: every entry in `targets_java.cpp` and
`targets_native.cpp` carries a `min_tier`, and the hook manager installs an entry only when
`min_tier <= effective tier`. The tier never changes code paths per target.

## What happens when you raise the tier today

Flutter, and every other statically linked BoringSSL, is a `max` surface, which the plan did not
expect. `libflutter.so` carries its own BoringSSL with hidden symbols, so there is no import slot;
the module instead locates BoringSSL's `ssl_crypto_x509_method` table (a struct of function pointers
in `.data.rel.ro`) and swaps its `session_verify_cert_chain` member for a wrapper that runs the
original (Dart's `badCertificateCallback`, WebRTC's verify callback, still fire) and returns success.
The write is a pointer in a data page of an app-private library, the same class as the bundled-TLS
GOT slots `max` already permits; no executable byte changes. The function is found by a heuristic
(the only code referencing the `"ssl_client"` / `"ssl_server"` purpose strings and reached through a
pointer table), so `tests/host/test_boringssl_table` runs the locator over real libraries (three
Flutter engines, WebRTC, OpenTok, Brella, plus an OpenSSL build that must *not* match) the way the
ELF contract check covers the system edges. The ladder reports `libflutter.so` as `flutter` and any
other library as `static_boringssl`.

Statically linked OpenSSL (1.1.1 and 3.x) is a `max` surface by the same reasoning
(`static_openssl`). OpenSSL has no x509 method table and its chain check is a direct call, but
every handshake runs through the client `SSL_METHOD`, a const struct of function pointers in
`.data.rel.ro` that `TLS_client_method()` returns. The module decodes that function's ADRP+ADD to
find the table, checks the version and option mask it starts with, and swaps the `ssl_connect`
member for a wrapper that lowers the object's verify mode to `SSL_VERIFY_NONE` (the app's callback
still runs), calls the original, and sets the stored verify result to `X509_V_OK`. One pointer in a
data page of an app-private library, no executable byte changed. It depends on four of the
library's exports, which is why a hidden-visibility OpenSSL reports `pattern_not_found` rather
than being guessed at; the host test runs the locator over an OpenVPN3 core that keeps them.

`INLINE_IN_PROVIDER` entries have no backend. For them, and for `compat`, raising the tier changes
only the coverage log:

- at `max`, a `balanced` entry whose library is present reports
  `present=yes reachable=no reason=tier required_tier=balanced current_tier=max`;
- at `balanced`, the same entry reports
  `present=yes reachable=no reason=backend_unavailable style=inline required_tier=balanced`.

Nothing louder is installed. When the inline backend ships, raising the tier will start installing
those entries without any change to the configuration format.

Flutter note for testing: `dart:io` ignores the Android HTTP proxy setting and user-installed CAs.
To see Flutter traffic in an interception proxy, redirect the app's TCP 443 to an invisible-proxy
listener with the per-package `redirect` key (`docs/reference.md`). The redirect is a firewall rule
installed by the root companion, outside the process, so it is available at every tier and changes
nothing a tier describes.

## When to escalate

Read the coverage lines first (`docs/coverage.md`). Escalate only when a line says
`present=yes reachable=no` with a `required_tier` above your current one, and only for that package.
If the lines show every present surface as reachable and the bypass still fails, a higher tier will
not help; the app is doing something the target tables do not cover (`docs/known-limitations.md`,
`docs/adding-hooks.md`).

A default of `max` is deliberate even though it leaves some apps unreached: a user who installs the
module and tests a Flutter or RASP-protected app will see it fail *with a line naming the tier to
try*, which is a better outcome than having been detectable in every other app the whole time.
