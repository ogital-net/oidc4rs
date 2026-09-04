# AGENTS.md

Conventions for AI coding agents and humans working on `oidc4rs`.
Living document; update when a rule changes. Do not edit historical
rationale.

## File encoding

- ASCII only. No UTF-8 in source, comments, identifiers, or string
  literals. The crate is consumed on systems with locale settings that
  mangle non-ASCII; assume the worst.

## Comments

- Minimal but complete. Every public item has a doc comment; every
  non-obvious private item has a one-line comment explaining why it
  exists.
- No history. Do not write "Previously this used X", "Refactored from Y",
  or "TODO from review". The git log is the history. Comments describe the
  current state only.
- No editorializing. Do not write "this is the right way" or "this is a
  known hack". Either the code is correct or it needs to be fixed.
- No authorship, no "Author:", no Signed-off-by in source.

## Style

- `cargo fmt` is the only formatter. Do not configure a different style.
- Every commit must pass `cargo fmt --check` and
  `cargo clippy --all-targets --all-features -- -D warnings`.
- Prefer `?` over `.unwrap()` / `.expect()`. The only allowed
  `.expect()`s are on paths that can never fail because of a static
  invariant (e.g. parsing a literal the program itself wrote).
- Prefer `&str` over `String` in function parameters; return owned data
  only when the caller needs ownership.
- Use `thiserror` for error enums; do not hand-roll `Display` impls.
- Use `serde` derives for JSON-shaped data; do not hand-write
  `Serialize`/`Deserialize` unless the format demands it.
- Newtypes over primitives for IDs and URLs. Do not pass `&str` where a
  `ClientId` / `IssuerUrl` is meant.

## Module organization

- One module per file. `mod.rs` re-exports.
- Public types live at the crate root or under a single level of
  re-exported module.
- `pub(crate)` for items used across modules but not exposed.
- No deep module nesting. Two levels of `pub mod` is the maximum.

## Cryptography

- All randomness and hashing go through `crate::crypto`. No `getrandom`,
  no `rand`, no `sha2`, no `ring`, no `aws-lc-rs` in any other module.
- `aws-lc-sys` / `boring-sys` are optional dependencies behind the
  `aws-lc` / `boring` features. Exactly one must be enabled; a
  `compile_error!` enforces it.
- Never `unwrap` an FFI result. Map non-success returns to
  `crypto::Error` variants.
- SAFETY comments on every `unsafe` block. Explain what is being
  dereferenced and why the caller upholds the invariant.

## Async

- The crate is async-only.
- All `async fn`s in public APIs return `BoxFuture<'_, T>`-shaped futures
  so callers are not pinned to a runtime. Use `pub type BoxFuture<'a, T>
  = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;`.
- No `tokio` / `async-std` / `smol` in `[dependencies]`. Callers wire
  their own runtime; `examples/` show the wiring for `reqwest` + tokio.
  Exception: the optional `hyper` feature
  (`transport::hyper_client::HyperHttpClient`) depends on
  `hyper-util`'s tokio-based connector, because no maintained
  runtime-agnostic TCP/TLS connector exists for hyper. This is an
  opt-in `AsyncHttpClient` implementation, not a runtime the rest of
  the crate depends on; callers who do not enable `hyper` are
  unaffected.

## Errors

- One crate-wide `OidcError` enum in `src/error.rs`. Modules add
  variants as needed.
- Each variant's `#[error("...")]` message is a complete sentence ending
  in no period (rustfmt convention).
- `From<...>` impls for foreign errors live in `error.rs`, not in the
  modules that use them.

## Dependencies

- Pin to major versions; allow minor bumps (`"1"` not `"1.2"`).
- Every new dependency must justify itself in the PR description. If
  `std` or an existing dependency covers it, do not add it.
- The `jose4rs` dependency is pinned to upstream `main` via a git
  rev. Refresh the rev when upstream changes; switch to a crates.io
  version once a release that includes the required APIs ships.

## Testing

- Unit tests live next to the code they test (`#[cfg(test)] mod tests`).
- Integration tests go in `tests/` at the crate root.
- Examples in `examples/` are also smoke tests; they must compile in CI.

## Commits

- One concern per commit.
- Commit message subject is imperative mood, <= 72 chars, no trailing
  period.
- Body wraps at 72 chars and explains *why*, not *what*.
