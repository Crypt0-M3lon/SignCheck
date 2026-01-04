# Copilot / AI agent instructions for SignCheck

Short, actionable guidance to help an AI coding assistant get productive quickly.

## Big picture
- Purpose: small Windows-only CLI that verifies PE code signatures using Win32 Crypto/WinTrust APIs (via the `windows` crate).
- Core logic: `src/main.rs` implements `check_signature(path, check_catalog)` which calls `WinVerifyTrust` and uses `CryptQueryObject`/`CryptMsgGetAndVerifySigner` to extract signer info.
- Test app: `test_apps/self_signed` is a minimal binary used to exercise self-signed scenarios.

## Key files
- [Cargo.toml](Cargo.toml) — project dependencies (notably `windows` and `chrono`).
- [src/main.rs](src/main.rs) — single-file CLI, Windows API usage, error mapping (`TrustError`).
- [scripts/create_self_signed_and_sign.ps1](scripts/create_self_signed_and_sign.ps1) — builds `test_apps/self_signed`, creates a self-signed cert, signs the exe (PowerShell; run elevated if needed).
- [test_apps/self_signed/src/main.rs](test_apps/self_signed/src/main.rs) — minimal test binary used by integration tests.

## Developer workflows (explicit)
- Build the CLI: `cargo build --release`.
- Run the CLI (single arg = path to file):
  - Example: `cargo run -- "C:\\path\\to\\target.exe"` (the binary expects exactly one path argument).
- Run tests: `cargo test` (note: some tests are `#[cfg(windows)]` and expect Windows environment and the test binary at `test_apps/self_signed/target/release/self_signed.exe`).
- Create & sign the test binary (Windows PowerShell, elevated): run `scripts\create_self_signed_and_sign.ps1` from repo root. It builds the test app and signs it with a self-signed cert placed in `CurrentUser\My` (not trusted by default).

- Required pre-commit checks: All code modifications must be formatted with `cargo fmt --all` and pass clippy with warnings treated as errors:
  - `cargo fmt --all`
  - `cargo clippy --all -- -D warnings`

## Project-specific patterns & conventions
- Platform: Windows-only usage of Win32 APIs via the `windows` crate — avoid proposing cross-platform replacements unless adding feature flags.
- Wide strings: paths are encoded using `encode_utf16().chain(Some(0))` before passing to Win32 functions; follow this pattern when manipulating wide strings.
- Error handling: HRESULTs are mapped to a `TrustError` enum via `hr_to_trust_error(hr)` — prefer adding new mappings to that function rather than scattering numeric checks.
- Catalog handling: `check_signature` accepts `check_catalog: bool` and will attempt to acquire a catalog admin context (via `CryptCATAdminAcquireContext2`) when set. The code currently defaults to `false` and has a commented fallback flow — preserve that intent when modifying behavior.
- Unsafe APIs: many Windows calls are wrapped in `unsafe` blocks. Limit unsafe surface and follow existing lifetime and cleanup patterns (e.g., `CertFreeCertificateContext`, `CryptMsgClose`, `CertCloseStore`, `CryptCATAdminReleaseContext`).

## Integration points & external dependencies
- `windows` crate — heavy usage of types like `WINTRUST_DATA`, `WINTRUST_FILE_INFO`, GUID constants, and WinTrust helper constants (e.g., `WTD_UI_NONE`).
- PowerShell script depends on `cargo` being in PATH and will create certificates via `New-SelfSignedCertificate` and sign via `Set-AuthenticodeSignature`.

## When changing or adding features
- If you add more Win32 calls, mirror existing resource cleanup patterns to avoid leaks.
- Add new HRESULT-to-`TrustError` mappings inside `hr_to_trust_error` and create focused unit tests in the `#[cfg(windows)]` test module in `src/main.rs`.
- Keep CLI surface minimal: maintain the single-argument usage or explicitly expand the usage message in `main()`.

- Lint & format requirement: any non-trivial change must include updated code that is formatted (`cargo fmt`) and compiles cleanly under `cargo clippy` using `-D warnings`. Add or update tests where appropriate.

- Tests requirement: Any change must preserve existing tests and ensure `cargo test` passes without modifying tests. Only modify tests when the user explicitly requests test updates; in that case clearly state which tests changed and why.

## Quick examples (copyable)
- Build and run against an exe:
  ```powershell
  cargo run -- "C:\\path\\to\\file.exe"
  ```
- Build, sign test binary, then run the related test (Windows elevated PowerShell):
  ```powershell
  .\scripts\create_self_signed_and_sign.ps1
  cargo test --test self_signed -- --nocapture
  ```

If any section is unclear or you'd like deeper examples (e.g., adding a new wrapper for `WinVerifyTrust`), tell me which area to expand.
