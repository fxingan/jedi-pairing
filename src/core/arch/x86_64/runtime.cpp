#include <stdint.h>

extern "C" {
    void embedded_pairing_core_arch_x86_64_fpbase_384_montgomery_reduce(void* res, void* a, const void* p, uint64_t inv_word);
    void embedded_pairing_core_arch_x86_64_bigint_768_multiply(void* res, const void* a, const void* b);
    void embedded_pairing_core_arch_x86_64_bigint_768_square(void* res, const void* a);
}

namespace embedded_pairing::core {
    void (*runtime_fpbase_384_montgomery_reduce)(void*, void*, const void*, uint64_t) = embedded_pairing_core_arch_x86_64_fpbase_384_montgomery_reduce;
    void (*runtime_bigint_768_multiply)(void*, const void*, const void*) = embedded_pairing_core_arch_x86_64_bigint_768_multiply;
    void (*runtime_bigint_768_square)(void*, const void*) = embedded_pairing_core_arch_x86_64_bigint_768_square;
}
