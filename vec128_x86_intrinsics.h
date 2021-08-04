// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef AEGIS_CIPHER_VEC128_X86_INTRINSIC_H_
#define AEGIS_CIPHER_VEC128_X86_INTRINSIC_H_
#ifdef __SSE2__
#ifdef __AES__

#include <emmintrin.h>  // SSE2
#include <stdint.h>
#include <wmmintrin.h>  // AES_NI instructions.
#include <xmmintrin.h>  // Datatype __mm128i

namespace security {

namespace aegis {

typedef __m128i Vec128;

inline Vec128 Vec128Load(const char *mem) {
  return _mm_loadu_si128(reinterpret_cast<const Vec128 *>(mem));
}

inline void Vec128Store(char *mem, Vec128 x) {
  _mm_storeu_si128(reinterpret_cast<Vec128 *>(mem), x);
}

inline Vec128 MakeVec128Epi64x(uint64_t n1, uint64_t n0) {
  return _mm_set_epi64x(n1, n0);
}

inline Vec128 MakeVec128BroadcastEpi8(uint8_t x) { return _mm_set1_epi8(x); }

inline bool Vec128Eq(Vec128 a, Vec128 b) {
  // Compare byte wise.
  // A byte in eq is 0xff if the corresponding byte in x and y are equal
  // and 0x00 if the corresponding byte in x and y are not equal.
  Vec128 eq = _mm_cmpeq_epi8(a, b);
  // Extract the 16 most significant bits of each byte in eq.
  int bits = _mm_movemask_epi8(eq);
  return 0xFFFF == bits;
}

inline Vec128 Vec128AesRound(Vec128 x, Vec128 y) {
  return _mm_aesenc_si128(x, y);
}

inline Vec128 Vec128And(Vec128 x, Vec128 y) { return _mm_and_si128(x, y); }

inline Vec128 Vec128AndNot(Vec128 x, Vec128 y) {
  return _mm_andnot_si128(x, y);
}

inline Vec128 Vec128Xor(Vec128 x, Vec128 y) { return _mm_xor_si128(x, y); }

inline Vec128 Vec128CmpLtEpi8(Vec128 x, Vec128 y) {
  return _mm_cmplt_epi8(x, y);
}

}  // namespace aegis

}  // namespace security

#else
#error AESNI instruction set required.
#endif  // __AES__
#else
#error SSE2 instruction set required.
#endif  // __SSE2__

#endif  // AEGIS_CIPHER_VEC128_X86_INTRINSICS_H_
