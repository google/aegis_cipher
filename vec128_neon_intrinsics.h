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

#ifndef AEGIS_CIPHER_VEC128_NEON_INTRINSIC_H_
#define AEGIS_CIPHER_VEC128_NEON_INTRINSIC_H_
#include "arm_neon.h"

namespace security {

namespace aegis {

typedef uint8x16_t Vec128;

inline Vec128 Vec128Load(const char *mem) {
  return vld1q_u8(reinterpret_cast<const uint8_t *>(mem));
}

inline void Vec128Store(char *mem, Vec128 x) {
  vst1q_u8(reinterpret_cast<unsigned char *>(mem), x);
}

inline Vec128 MakeVec128Epi64x(uint64_t n1, uint64_t n0) {
  uint64x2_t c = vcombine_u64(vcreate_u64(n0), vcreate_u64(n1));
  return vreinterpretq_u8_u64(c);
}

inline Vec128 MakeVec128BroadcastEpi8(uint8_t x) { return vdupq_n_u8(x); }

inline bool Vec128Eq(Vec128 a, Vec128 b) {
  uint64x2_t res = vceqq_u64(vreinterpretq_u64_u8(a), vreinterpretq_u64_u8(b));
  return vminvq_u32(res) != 0;
}

inline Vec128 Vec128AesRound(Vec128 state, Vec128 round_key) {
  return veorq_u8(vaesmcq_u8(vaeseq_u8(state, vdupq_n_u8(0))), round_key);
}

inline Vec128 Vec128And(Vec128 x, Vec128 y) { return vandq_u8(x, y); }

inline Vec128 Vec128AndNot(Vec128 x, Vec128 y) { return vbicq_u8(y, x); }

inline Vec128 Vec128Xor(Vec128 x, Vec128 y) { return veorq_u8(x, y); }

inline Vec128 Vec128CmpLtEpi8(Vec128 x, Vec128 y) { return vcltq_s8(x, y); }

}  // namespace aegis

}  // namespace security

#endif  // AEGIS_CIPHER_VEC128_NEON_INTRINSICS_H_
