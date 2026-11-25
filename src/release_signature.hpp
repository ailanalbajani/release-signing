#pragma once
// Offline-signed release manifests for a Windows updater. Windows CNG only.
// Include after <Windows.h> and <bcrypt.h>; link bcrypt.lib.
//
// Trust model: the manifest server and every download host are untrusted
// transport. A release is accepted only if `artifacts_sig` (ECDSA P-256 over
// SHA-256, raw r||s, base64) verifies against a public key compiled into the
// client, for exactly the version, sizes and hashes being installed.
//
// Message() and tools/sign-release.mjs must build the same text byte for byte.

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace release_sig {

// Canonical order of the signed files. Edit together with the signing tool.
inline constexpr const char* kFiles[] = { "app.exe", "core.dll", "ui.zip" };
inline constexpr size_t kFileCount = sizeof(kFiles) / sizeof(kFiles[0]);

struct PublicKey { unsigned char x[32], y[32]; };

struct File {
    int64_t     size = -1;
    std::string sha256;   // lowercase hex
    std::string url;      // not signed: the hash pins the content
};

struct Release {
    std::string version;
    File        files[kFileCount];
    bool        valid = false;   // signature verified and every file pinned
};

inline bool Pinned(const File& f) {
    if (f.size <= 0 || f.sha256.size() != 64) return false;
    for (char c : f.sha256)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

inline bool PlainVersion(std::string_view v) {
    if (v.empty() || v.size() > 64) return false;
    for (char c : v)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == '.' || c == '-')) return false;
    return true;
}

inline std::string Message(const Release& r) {
    std::string m = "release-v1\nversion=" + r.version + "\n";
    for (size_t i = 0; i < kFileCount; ++i) {
        m += kFiles[i]; m += '|';
        m += std::to_string(r.files[i].size); m += '|';
        m += r.files[i].sha256; m += '\n';
    }
    return m;
}

inline bool Base64Decode(std::string_view in, std::vector<unsigned char>& out) {
    out.clear();
    uint32_t acc = 0; int bits = 0;
    for (char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else if (c == '=') break;
        else return false;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((unsigned char)(acc >> bits)); }
    }
    return true;
}

inline bool Verify(const PublicKey& pub, const std::string& message, std::string_view sigB64) {
    std::vector<unsigned char> sig;
    if (sigB64.empty() || !Base64Decode(sigB64, sig) || sig.size() != 64) return false;

    std::array<unsigned char, 32> digest{};
    BCRYPT_ALG_HANDLE sha = nullptr;
    if (BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    const bool hashed = BCryptHash(sha, nullptr, 0, (PUCHAR)message.data(), (ULONG)message.size(),
                                   digest.data(), (ULONG)digest.size()) >= 0;
    BCryptCloseAlgorithmProvider(sha, 0);
    if (!hashed) return false;

    struct { BCRYPT_ECCKEY_BLOB hdr; unsigned char xy[64]; } blob{};
    blob.hdr.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    blob.hdr.cbKey = 32;
    memcpy(blob.xy, pub.x, 32);
    memcpy(blob.xy + 32, pub.y, 32);

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) >= 0) {
        if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key,
                                (PUCHAR)&blob, (ULONG)sizeof(blob), 0) >= 0) {
            ok = BCryptVerifySignature(key, nullptr, digest.data(), (ULONG)digest.size(),
                                       sig.data(), (ULONG)sig.size(), 0) >= 0;
            BCryptDestroyKey(key);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

// --- minimal manifest reader -------------------------------------------------
// Not a general JSON parser. Ambiguity is not a security issue here: whatever
// values are read must reproduce the signed text, and those same values are
// the ones the caller installs from.

inline size_t FindKey(std::string_view body, std::string_view key) {
    std::string pat = "\"" + std::string(key) + "\"";
    size_t p = body.find(pat);
    if (p == std::string_view::npos) return p;
    p = body.find(':', p + pat.size());
    if (p == std::string_view::npos) return p;
    ++p;
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t' || body[p] == '\r' || body[p] == '\n')) ++p;
    return p;
}

inline std::string String(std::string_view body, std::string_view key) {
    size_t p = FindKey(body, key);
    if (p == std::string_view::npos || p >= body.size() || body[p] != '"') return {};
    std::string out;
    for (size_t i = p + 1; i < body.size(); ++i) {
        char c = body[i];
        if (c == '\\' && i + 1 < body.size()) { out += body[++i]; continue; }
        if (c == '"') return out;
        out += c;
    }
    return {};
}

inline int64_t Int(std::string_view body, std::string_view key) {
    size_t p = FindKey(body, key);
    if (p == std::string_view::npos) return -1;
    int64_t v = 0; int digits = 0;
    for (; p < body.size() && body[p] >= '0' && body[p] <= '9'; ++p) {
        if (++digits > 15) return -1;
        v = v * 10 + (body[p] - '0');
    }
    return digits ? v : -1;
}

inline std::string_view Object(std::string_view body, std::string_view key) {
    size_t p = FindKey(body, key);
    if (p == std::string_view::npos || p >= body.size() || body[p] != '{') return {};
    int depth = 0; bool str = false;
    for (size_t i = p; i < body.size(); ++i) {
        char c = body[i];
        if (str) { if (c == '\\') ++i; else if (c == '"') str = false; continue; }
        if (c == '"') str = true;
        else if (c == '{') ++depth;
        else if (c == '}' && --depth == 0) return body.substr(p, i - p + 1);
    }
    return {};
}

// One parse feeds both the signature check and the installer, so two readers
// can never disagree about what was verified.
inline Release Parse(const PublicKey& pub, std::string_view manifest) {
    Release r;
    r.version = String(manifest, "version");
    bool pinned = PlainVersion(r.version);
    std::string_view arts = Object(manifest, "artifacts");
    for (size_t i = 0; i < kFileCount; ++i) {
        std::string_view f = Object(arts, kFiles[i]);
        if (!f.empty()) {
            r.files[i].size = Int(f, "size");
            r.files[i].sha256 = String(f, "sha256");
            r.files[i].url = String(f, "url");
        }
        pinned = pinned && Pinned(r.files[i]);
    }
    r.valid = pinned && Verify(pub, Message(r), String(manifest, "artifacts_sig"));
    return r;
}

// Streams a downloaded file and compares it with the signed entry.
// `read(buf, cap)` returns bytes read, 0 at end, negative on error.
template <class Read>
bool Matches(const File& want, Read&& read) {
    if (!Pinned(want)) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    bool ok = BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) >= 0;
    std::vector<char> buf(1 << 16);
    int64_t total = 0;
    while (ok) {
        const int n = read(buf.data(), (int)buf.size());
        if (n == 0) break;
        ok = n > 0 && BCryptHashData(h, (PUCHAR)buf.data(), (ULONG)n, 0) >= 0;
        total += n;
    }
    unsigned char d[32]{};
    if (ok) ok = BCryptFinishHash(h, d, sizeof(d), 0) >= 0;
    if (h) BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok || total != want.size) return false;
    std::string hex;
    for (unsigned char b : d) { hex += "0123456789abcdef"[b >> 4]; hex += "0123456789abcdef"[b & 15]; }
    return hex == want.sha256;
}

} // namespace release_sig
