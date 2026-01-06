# Copilot / AI agent instructions for SignCheck

Short, actionable guidance to help an AI coding assistant get productive quickly.

## Big picture
- Purpose: small Windows-only CLI that verifies PE code signatures (both embedded Authenticode and catalog-based) using Win32 Crypto/WinTrust APIs (via the `windows` crate).
- Core logic: `src/main.rs` implements:
  - `check_embedded_signatures(path)` — verifies embedded (Authenticode) signatures via `WinVerifyTrust`
  - `check_catalog_signatures(path)` — computes file hash and verifies against system catalogs
  - `extract_signer_info(path)` — extracts certificate info via `CryptQueryObject`/`CryptMsgGetAndVerifySigner`
  - Both functions always run; file considered signed if **at least one signature type is valid**
- Key structs: `VerificationResult` holds file path, status, cert path, and signature type flag
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
- **Signature verification logic**: Both embedded and catalog checks always run; `main()` combines results and treats file as signed if either signature type is valid. This ensures comprehensive verification.
- Platform: Windows-only usage of Win32 APIs via the `windows` crate — avoid proposing cross-platform replacements unless adding feature flags.
- **Wide strings**: paths are encoded using `encode_utf16().chain(std::iter::once(0))` before passing to Win32 functions; follow this pattern when manipulating wide strings.
- **Error handling**: HRESULTs are mapped to a `TrustError` enum via `hr_to_trust_error(hr)` — prefer adding new mappings to that function rather than scattering numeric checks. Both `TrustError` and `SignatureStatus` implement `Clone` and `PartialEq` for easier composition.
- **Resource cleanup**: All Win32 handles and contexts must be explicitly released. Catalog functions require paired `CryptCATAdminReleaseCatalogContext` + `CryptCATAdminReleaseContext` calls; WinVerifyTrust state requires `WTD_STATEACTION_CLOSE` before returning. Use early returns in error paths but **always clean up** before returning.
- **Unsafe APIs**: Many Windows calls are wrapped in `unsafe` blocks. Limit unsafe surface and follow existing lifetime and cleanup patterns (e.g., `CertFreeCertificateContext`, `CryptMsgClose`, `CertCloseStore`, `CryptCATAdminReleaseContext`, `CryptCATAdminReleaseCatalogContext`).
- **Constants**: Define magic numbers at the top (e.g., `MAX_SUBJECT_NAME_LEN`, `MAX_CATALOG_PATH_LEN`). Time conversion uses `FILETIME_TO_UNIX_EPOCH` and `HUNDRED_NANOSECONDS_PER_SECOND`.
- **Display trait**: `SignerInfo` and `TrustError` implement `fmt::Display` for clean console output. Use these when printing to stdout.

## Integration points & external dependencies
- `windows` crate — heavy usage of types like `WINTRUST_DATA`, `WINTRUST_FILE_INFO`, GUID constants, and WinTrust helper constants (e.g., `WTD_UI_NONE`).
- PowerShell script depends on `cargo` being in PATH and will create certificates via `New-SelfSignedCertificate` and sign via `Set-AuthenticodeSignature`.

## When changing or adding features
- **Signature verification**: The dual-check design (embedded + catalog) is intentional. If modifying either check, ensure both continue to run and the "at least one valid" logic is preserved.
- If you add more Win32 calls, mirror existing resource cleanup patterns to avoid leaks. **Critical**: catalog operations must always release both the catalog context handle and the admin context.
- Add new HRESULT-to-`TrustError` mappings inside `hr_to_trust_error()` and add corresponding test cases in the `#[cfg(windows)]` test module.
- When refactoring, be mindful of `VerificationResult`'s responsibility — it should contain the minimal set of data needed to report verification outcomes and extract signer info.
- Keep CLI surface minimal: maintain the single-argument usage or explicitly expand the usage message in `main()`.

- **Lint & format requirement**: Any non-trivial change must:
  - Be formatted with `cargo fmt --all`
  - Compile cleanly under `cargo clippy --all -- -D warnings` (no warnings allowed)
  - Pass all tests with `cargo test`

- **Tests requirement**: Any change must preserve existing tests. Only modify tests when user explicitly requests updates. Current tests cover:
  - Firefox embedded signature validation
  - Self-signed certificate rejection
  - Catalog signature detection and verification

## Quick examples (copyable)
- Build and run against an exe:
  ```powershell
  cargo run -- "C:\\path\\to\\file.exe"
  ```
- Run with release optimization:
  ```powershell
  cargo build --release
  .\target\release\SignCheck.exe "C:\\path\\to\\file.exe"
  ```
- Build, sign test binary, then run the related test (Windows elevated PowerShell):
  ```powershell
  .\scripts\create_self_signed_and_sign.ps1
  cargo test
  ```
- Format and validate before committing:
  ```powershell
  cargo fmt --all
  cargo clippy --all -- -D warnings
  cargo test
  ```

## Key implementation notes
- **VerificationResult**: Returned by both `check_embedded_signatures()` and `check_catalog_signatures()`. Encapsulates all metadata needed for reporting and signer extraction.
- **SignerInfo**: Contains subject, valid_from, and valid_to. Implements `Display` for clean console output.
- **Main logic**: Calls both checks, then evaluates both statuses. If either is `SignedAndValid`, the file is signed. Useful signer info is extracted from whichever signature was valid (catalog takes priority if both valid).

If any section is unclear or you'd like deeper examples (e.g., adding a new wrapper for `WinVerifyTrust`), tell me which area to expand.
