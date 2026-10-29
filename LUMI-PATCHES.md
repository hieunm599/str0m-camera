# Lumi Str0m 0.24.1 patch branch

Base: upstream tag `0.24.1`, commit
`8c4c5284cb11b1e3c82962639cda5b3e95af73e8` from algesten/str0m.
This branch ports the existing validated Lumi vendor modifications without
changing Rust source bytes. Hardware AES/mbedTLS providers remain separate
application-owned crates; this repository owns only core/provider patches.

## Changes

- SRTP/SRTCP encryption failures return no output instead of panicking; session
  drops empty results. Application hardware latch checks still guard polling
  and transmission. No CPU fallback, profile, key or pacing change.
- Optional `pipeline-profile` and `work-profile` instrumentation. Disabled
  builds retain the existing uninstrumented behavior.
- RustCrypto GCM uses the caller output buffer, and optional provider work
  ledger shares the caller accounting context.

## Cargo integration

Fork packages are `str0m-lumi` 0.24.1 and `str0m-rust-crypto-lumi` 0.6.0,
keeping library names `str0m` and `str0m_rust_crypto`. Distinct package names
allow registry and patched engines to coexist with explicit release profiles.
Ordinary/native application builds continue to use registry Str0m exactly 0.24.1.
Only hardware AES and intrusive profiling select the pinned Git revision.

Use registry `str0m-proto = "=0.7.0"` for shared public crypto trait identity.
Using this repository's path proto would produce incompatible types alongside
the application's registry provider crates. Use published `is = "=0.11.1"`
and dimpl exactly 0.7.5 to preserve the existing production dependency graph.
The application retains its separate dimpl profile API and CTR batching patches.

## Validation

Run `cargo test -p str0m-lumi --no-default-features --features rust-crypto --lib srtp`
and `cargo test -p str0m-rust-crypto-lumi --lib`. Application integration must
also check hardware failure latches, DTLS profiles, adapter feature combinations
and target ABI. Build/host correctness is not board CPU/FPS qualification.

## Ported source hashes

These hashes must match the pre-migration application source byte for byte.

- `crypto/rust-crypto/src/lib.rs`: `02ee281a4dbff47304acf6ab7fb975da7b1e5375397002a08a4dff25fc95f677`
- `crypto/rust-crypto/src/srtp.rs`: `7dcc2395b9cad1bcf9cc51a3b268179063bea99fd57a60f28e6f3fa514349e92`
- `crypto/rust-crypto/src/work_profile.rs`: `2ab81d3f823eab26c78861ea38412731cacbc3d90cd5886d24212f74b86d40dd`
- `src/lib.rs`: `26a3d47b41f428b6db9ffce7b78ed81bbeb9253d6b5dca95c7779069984b74d6`
- `src/pipeline_profile.rs`: `89f46d81094ce690d329276120da9ebf284ae1c2e7480ecfb02a1945d85023f6`
- `src/rtp/srtp.rs`: `6cd721eb1e0aaee80f66a15a5037cc62c77b11a4778c2dd2fb9d75a86de6a872`
- `src/session.rs`: `7af38e5d2dbbb309d18fd4e1579c19bde869372dc1ebdb445efbbbaadc1789af`
- `src/streams/rtx_cache.rs`: `90f357ada5916f112632bbf552e50567e4b3d8fdda3507006d383660923100ef`
- `src/streams/send.rs`: `322c5bc631ddbf9521165d6dd39c28711407a60b25e1229f4d91a71d723d1017`
- `src/work_profile.rs`: `5df27b68809efc9f72a81150d7304a26fb9b6e61e5b8f84cba2fcea17851969a`
