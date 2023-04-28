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

#ifndef AEGIS_CIPHER_VEC128_PPC_INTRINSIC_H_
#define AEGIS_CIPHER_VEC128_PPC_INTRINSIC_H_
#include <altivec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace security {

namespace aegis {

// This implementation of Vec128 for PPC is keeping the vector content in
// big-endian format, as the AES round transformation is implemented for
// big-endian on PPC. As our AEGIS implementation assumes little-endian for
// key/iv/plaintext/ciphertext, we convert little-endian<->big-endian on
// load, stores and uint64 conversion.

typedef vector unsigned char Vec128;

inline Vec128 Vec128Load(const char *mem) {
  // Load from memory with an endian conversion.
  return vec_xl_be(0, reinterpret_cast<const unsigned char *>(mem));
}

inline void Vec128Store(char *mem, Vec128 x) {
  // Store to memory with an endian conversion.
  vec_xst_be(x, 0, reinterpret_cast<unsigned char *>(mem));
}

inline Vec128 MakeVec128Epi64x(uint64_t end_le, uint64_t start_le) {
  // All uint64_t constants in aegis128L.cc are stated with the assumption that
  // when stored to memory result in a little endian ordering. So we need to
  // convert both uint64_t given.
  vector unsigned long long le =
      vec_insert(end_le, vec_promote((unsigned long long)start_le, 1), 0);
  // Reverse elements on the 16 byte vector to convert to big endian.
  return vec_revb(le);
}

inline Vec128 MakeVec128BroadcastEpi8(uint8_t x) { return vec_splat_u8(x); }

inline bool Vec128Eq(Vec128 a, Vec128 b) { return vec_all_eq(a, b) != 0; }

inline Vec128 Vec128AesRound(Vec128 state, Vec128 round_key) {
  return vec_cipher_be(state, round_key);
}

inline Vec128 Vec128And(Vec128 x, Vec128 y) { return vec_and(x, y); }

inline Vec128 Vec128AndNot(Vec128 x, Vec128 y) { return vec_andc(y, x); }

inline Vec128 Vec128Xor(Vec128 x, Vec128 y) { return vec_xor(x, y); }

inline Vec128 Vec128CmpLtEpi8(Vec128 x, Vec128 y) {
  // This API implements a signed comparison, therefore cast from 'unsigned
  // char' to 'signed char'. We do implement this API as signed comparison
  // solely because Intel intrinsics don't have an unsigned comparison on
  // unsigned ints.
  return vec_cmplt((vector signed char)x, (vector signed char)y);
}

}  // namespace aegis

}  // namespace security

#endif  // AEGIS_CIPHER_VEC128_PPC_INTRINSICS_H_
