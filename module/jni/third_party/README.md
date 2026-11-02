# third_party

Empty on purpose in Phase 1. The `max` tier uses only the in-tree GOT rewriter (`got/`) and the
DEX patcher (`dex/`); no hooking library is linked into target processes.

shadowhook (ByteDance, Apache-2.0) arrives here as a pinned submodule with Phase 1.5, behind the
`INLINE_IN_PROVIDER` / `PATTERN` hook styles that only the `balanced` tier may select. It was not
vendored earlier because an unreachable inline-hook backend would still add its code and data to
every target process's mapping of our library, which is footprint for nothing.
