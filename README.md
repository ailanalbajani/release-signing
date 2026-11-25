# release-signing

Offline-signed release manifests for Windows updaters: a header-only C++20 verifier built on Windows CNG,
a Node signer, and tamper tests.

## Problem

An updater that trusts its manifest server is only as safe as that server. Common failures
(CWE-494, CWE-345):

- Hash checking is optional, so removing the hashes disables it.
- The manifest holds the hashes but is itself unsigned, so whoever controls it controls both.
- A truncated download is treated as complete.
- The verifier and the installer parse the manifest separately and can be made to disagree.

## Design

1. **Offline signature.** ECDSA P-256 over a canonical text holding the version and each file's name,
   size and SHA-256. The private key stays off every server; the public key is compiled into the client.
2. **Fail closed.** An unsigned, partly pinned or mismatching release is refused.
3. **One parse.** The values that are verified are the values that are installed, so duplicate JSON keys
   cannot split them.
4. **URLs are not signed.** The hash pins the content, so mirrors can change without re-signing.

When adding this to an existing updater, publish the signed manifest before shipping the client that
requires it. Otherwise the client will correctly refuse every update.

## Not solved

- **Replay.** An older, correctly signed release still verifies. Compare versions, and add a signed
  timestamp or expiry if fresh installs need protection.
- **Local attacker.** Verify again when applying staged files if they sit in a user-writable directory.
- **Ordering.** Download to a temporary location and move into place only after `Matches()` succeeds.
- **Key loss or theft.** One compiled-in key, no revocation.

## Use

| Path | Contents |
|---|---|
| `src/release_signature.hpp` | Manifest reader, signature check, file check |
| `tools/sign-release.mjs` | Signs a full release directory |
| `tests/` | 22 accept/reject cases with a throwaway key |

Edit the file list in the header and the signer together.

```
node tests/run.mjs      # Windows, Visual Studio 2022 C++ tools, Node 18+
```

Result on 2026-11-25 (MSVC v143, `/W4 /WX`): 22/22 passed. The last case documents the replay limit.
