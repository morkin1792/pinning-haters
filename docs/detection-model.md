# Detection model

Every mechanical decision in pinning-haters follows from one ranking: the hooking primitives,
ordered by how likely a real app is to notice them. When two designs reach the same surface, the one
using the lower-numbered primitive wins. This document is the user-facing version of that ranking;
the reasoning behind individual choices is in `AGENTS.md`.

## Priority order

1. **Low detectability.** Between equal-coverage designs, pick the one that modifies less of the
   target process, in the places least likely to be checked.
2. **Coverage.**
3. **Maintainability.**
4. **Convenience.** Never traded against item 1.

Coverage that cannot be obtained quietly is exposed as an opt-in tier, per package, never as a
default (`docs/stealth-tiers.md`).

## The primitive ranking, quietest first

| # | Primitive | What detects it | Seen outside RASP? |
|---|---|---|---|
| 1 | DEX bytecode patched in memory before verification | comparing the in-memory DEX with the APK's DEX | effectively never |
| 2 | Companion-side file operations outside the app process (oat eviction, config, logs) | nothing in-process; only noticing that oat artifacts are absent | effectively never |
| 3 | GOT/PLT slot rewrite in a *system* library (`libart`, `libdexfile`, `libnativeloader`, `libjavacrypto`) | snapshotting the GOT at load and re-reading it; checking that each slot points inside the expected provider | rare |
| 4 | GOT/PLT slot rewrite in an *app-private* library | the same, and app libraries are the first thing a scanner walks | uncommon |
| 5 | Inline `.text` patch in a system library | CRC of that library's executable segment against the file on disk | uncommon |
| 6 | Inline `.text` patch in libc | the same, and libc is the most CRC-checked library on the device | common |
| 7 | ArtMethod entry-point flip (LSPlant / Xposed style) | an entry point outside the legitimate `.oat` mapping | common; this is the standard Xposed check |

`max`, the default tier, uses 1, 2 and 3, plus 4 only for app-bundled TLS where there is no other
way to reach the surface. `balanced` adds 5. `compat` adds 6 and 7. The version shipping as v0.1.0
implements `max` only.

## What a target process contains at `max`

- Our `.so`, mapped, but as four anonymous regions: after the hooks are in, the module copies its
  own pages into anonymous memory and `mremap`s them over the originals (`hide.self_remap`, default
  on; Magisk Zygisk's `remap_all` technique). Same addresses, so every GOT slot that points into us
  keeps working; nothing outside our mapping is touched. What remains visible is the host's: Zygisk
  Next 1.4.5 keeps `/data/adb/modules/zygisksu/lib64/libzygisk.so` mapped by path in every process
  where a module stays loaded, and that is what a maps walk finds now. On Zygisk Next the module is
  loaded by the host's own linker, so `dl_iterate_phdr` never listed us; on a bionic-loaded host the
  soinfo entry would still name the path (the init log says which case applies). An anonymous
  executable region is itself a weaker signal that a RASP can look for.
- A handful of rewritten GOT slots in ART APEX and conscrypt APEX libraries: `adler32` in
  `libdexfile.so`, `SSL_set_custom_verify` in `libjavacrypto.so`, `android_dlopen_ext` in
  `libnativeloader.so` and `libart.so`, and the `stat`/`open`/`access` imports of the ART libraries
  that carry them.
- Rewritten GOT slots in app-private libraries only if the app bundles its own `libssl`/`libcrypto`
  consumers.
- Modified instruction bytes inside the app's own in-memory DEX, for the methods in the Java target
  table that the app actually ships.
- With logging enabled: one extra socket file descriptor, open to the companion.
- **No modified executable bytes anywhere.** No additional threads. No additional mappings beyond
  our `.so` and its allocations. No files of ours opened from inside the process.

Because nothing in any `.text` segment changes, the memory-versus-disk CRC check that catches inline
hooks has nothing to find, and the entire CRC-countermeasure problem (dumping post-hook text,
redirecting disk reads, intercepting raw syscalls) does not arise at this tier. That is a large body
of engineering the default configuration never needs.

In processes that are not configured targets the module leaves nothing: it unloads itself in
`preAppSpecialize`. It never attaches to `system_server`.

## Things never done, at any tier

- Hooking libc functions in order to *hide ourselves*: filtering `/proc/self/maps`, `smaps`,
  `status`, `dl_iterate_phdr`, hiding `/data/adb/pinning_haters/*`, spoofing properties. Each one
  requires an inline patch of libc (primitive 6). It would defend only against apps that already
  hunt for injected libraries, that is, RASP, while making the module strictly more detectable to
  every app that does not. Hiding our library is the host's job; the `/data/adb` paths are never
  touched from inside the app process anyway, so a hook there would create the exposure it was meant
  to remove.
- Allocating RWX pages.
- Any outbound network request.
- Touching a surface in a process that was not configured as a target.

## The GOT limitation

A GOT slot exists only for a call that crosses a library boundary through the PLT. There is no slot,
and therefore nothing for the default tier to rewrite, when:

- the provider and the consumer are the **same library** (a statically linked BoringSSL calling its
  own verification routine, Flutter's internal BoringSSL, Cronet);
- the library was linked with **`-Bsymbolic`** or the symbol was otherwise bound at link time;
- the import is a **data** symbol rather than a function (those live in `.rela.dyn`, which the
  rewriter deliberately does not parse);
- the consumer simply does not import that symbol on this Android version (the contract moved).

`got::has_edge()` is how the module discovers this, and the coverage ladder reports it: a named
consumer without the slot produces `reason=contract_missing`; a surface that needs an inline or
pattern hook is reported with `required_tier=balanced` (and `reason=backend_unavailable` once the
tier is raised, until that backend ships). Nothing falls back to a louder primitive silently.

## What detects `max`

`max` is quiet, not invisible. The checks that do work against it, all of which require an app to
be hunting deliberately, are listed in `docs/threat-model.md`: a GOT snapshot comparison, an
in-memory-DEX versus APK-DEX comparison, noticing that oat artifacts are absent, and (with logging
on) noticing an unexpected socket descriptor.

## Function-pointer tables are GOT-class

A pointer in a library's RELRO that happens not to be an import slot (BoringSSL's
`ssl_crypto_x509_method` inside `libflutter.so`, for example) has the same detection profile as a
GOT slot: a data page, text byte-identical to disk, caught only by snapshot-and-compare of that
table. The Flutter backend uses one, at `max`. The slot is found by a heuristic over strings and
relocations rather than by a CI-verified ELF contract, which is why `tests/host/test_flutter` runs
that heuristic over real engine builds.
