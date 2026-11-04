// Prints the challenges of barretenberg's native Poseidon2 and Keccak transcripts for a fixed sequence of prover
// messages; the output is transcript_challenges.txt.
//
// Built against barretenberg v6.0.0 (aztec-packages tag v6.0.0, commit 0219f11d8133970df3974fe5ae65e006bf8c193a)
// with clang 20. From barretenberg/cpp (with ipc-runtime/ next to barretenberg/):
//   cmake --preset default -DAVM=OFF
//   ninja -C build transcript crypto_poseidon2 crypto_keccak ecc numeric common env
//   clang++ -std=c++20 -O2 -DNO_PAR_ALGOS -I src -I build/_deps/msgpack-c/src/msgpack-c/include \
//     -I build/_deps/tracy-src/public /path/to/transcript_challenges.cpp -L build/lib -Wl,--start-group \
//     -ltranscript -lcrypto_poseidon2 -lcrypto_keccak -lecc -lnumeric -lcommon -lenv -Wl,--end-group \
//     -pthread -o transcript_challenges
#include "barretenberg/crypto/keccak/keccak.hpp"
#include "barretenberg/transcript/transcript.hpp"
#include <iostream>

template <typename Transcript> void emit(const char* name)
{
    Transcript transcript;
    transcript.send_to_verifier("data0", bb::fr(1));
    transcript.send_to_verifier("data1", bb::fr(2));
    transcript.send_to_verifier("point", bb::g1::affine_one);
    auto first =
        transcript.template get_challenges<bb::fr>(std::array<std::string, 2>{ "eta", "rom_logup_gamma" });
    for (auto value : first) {
        std::cout << name << " " << uint256_t(value) << "\n";
    }
    std::cout << name << " " << uint256_t(transcript.template get_challenge<bb::fr>("tail")) << "\n";
    transcript.send_to_verifier("data2", bb::fr(0xdeadbeef));
    transcript.send_to_verifier("large", -bb::fr(1));
    auto second =
        transcript.template get_challenges<bb::fr>(std::array<std::string, 3>{ "alpha", "beta", "gamma" });
    for (auto value : second) {
        std::cout << name << " " << uint256_t(value) << "\n";
    }
    std::cout << name << " " << uint256_t(transcript.template get_challenge<bb::fr>("delta")) << "\n";
}

int main()
{
    emit<bb::NativeTranscript>("poseidon2");
    emit<bb::KeccakTranscript>("keccak");
}
