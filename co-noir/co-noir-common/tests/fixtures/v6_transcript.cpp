// Independent challenge oracle for AztecProtocol/aztec-packages v6.0.0-rc.6.
// Release commit: 0df91ba1799012435c62c6108a0926b357fef88c.
// Uses the pinned C++ transcript and codec implementations, not a reimplementation.
// Compile from the oracle checkout's cpp directory, with its built static libraries:
// clang++ -std=c++20 -O2 -march=skylake -DNO_PAR_ALGOS -I src \
//   -I build/_deps/msgpack-c/src/msgpack-c/include -I build/_deps/tracy-src/public \
//   /path/to/v6_transcript.cpp -L build/lib -Wl,--start-group \
//   -ltranscript -lcrypto_poseidon2 -lcrypto_keccak -lecc -lnumeric -lcommon -lenv \
//   -Wl,--end-group -pthread -o /tmp/v6_transcript
#include "barretenberg/transcript/transcript.hpp"
#include "barretenberg/crypto/keccak/keccak.hpp"
#include <iostream>

template <typename Transcript> void emit(const char* name)
{
    Transcript transcript;
    transcript.send_to_verifier("data0", bb::fr(1));
    transcript.send_to_verifier("data1", bb::fr(2));
    transcript.send_to_verifier("point", bb::g1::affine_one);
    auto first = transcript.template get_challenges<bb::fr>(
        std::array<std::string, 2>{ "eta", "rom_logup_gamma" });
    for (auto value : first) { std::cout << name << " " << uint256_t(value) << "\n"; }
    std::cout << name << " " << uint256_t(transcript.template get_challenge<bb::fr>("tail")) << "\n";
    transcript.send_to_verifier("data2", bb::fr(0xdeadbeef));
    transcript.send_to_verifier("large", -bb::fr(1));
    auto second = transcript.template get_challenges<bb::fr>(
        std::array<std::string, 3>{ "alpha", "beta", "gamma" });
    for (auto value : second) { std::cout << name << " " << uint256_t(value) << "\n"; }
    std::cout << name << " " << uint256_t(transcript.template get_challenge<bb::fr>("delta")) << "\n";
}

int main()
{
    emit<bb::NativeTranscript>("poseidon2");
    emit<bb::KeccakTranscript>("keccak");
}
