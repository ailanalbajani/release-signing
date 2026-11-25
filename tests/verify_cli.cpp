// verify_cli <pubkey hex, x||y> <manifest> <release dir>
// Exit: 0 accepted, 10 release rejected, 11 a file does not match, 2 usage/IO.
#include <Windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <fstream>
#include <iterator>
#include "../src/release_signature.hpp"

int main(int argc, char** argv) {
    if (argc != 4 || strlen(argv[1]) != 128) return 2;
    release_sig::PublicKey pub{};
    for (int i = 0; i < 64; ++i) {
        unsigned b = 0;
        if (sscanf_s(argv[1] + i * 2, "%2x", &b) != 1) return 2;
        (i < 32 ? pub.x[i] : pub.y[i - 32]) = (unsigned char)b;
    }
    std::ifstream m(argv[2], std::ios::binary);
    if (!m) return 2;
    const std::string body((std::istreambuf_iterator<char>(m)), {});
    const auto rel = release_sig::Parse(pub, body);
    if (!rel.valid) return 10;
    for (size_t i = 0; i < release_sig::kFileCount; ++i) {
        std::ifstream f(std::string(argv[3]) + "/" + release_sig::kFiles[i], std::ios::binary);
        if (!f) return 11;
        const bool ok = release_sig::Matches(rel.files[i], [&](char* p, int cap) {
            f.read(p, cap);
            return f.bad() ? -1 : (int)f.gcount();
        });
        if (!ok) return 11;
    }
    return 0;
}
