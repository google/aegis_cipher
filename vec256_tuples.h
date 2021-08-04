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

#ifndef AEGIS_CIPHER_VEC256_TUPLES_H_
#define AEGIS_CIPHER_VEC256_TUPLES_H_

#include <tuple>

#include "vec128.h"

namespace security {

namespace aegis {

typedef std::tuple<Vec128, Vec128> Vec256;

inline void Vec256Store(char *mem, Vec256 x) {
  Vec128 block1;
  Vec128 block2;
  std::tie(block1, block2) = x;
  Vec128Store(mem, block1);
  Vec128Store(mem + 16, block2);
}

inline Vec256 MakeVec256(Vec128 x, Vec128 y) { return std::make_tuple(x, y); }

inline Vec256 Vec256Xor(Vec256 x, Vec256 y) {
  Vec128 x1, x2;
  Vec128 y1, y2;
  std::tie(x1, x2) = x;
  std::tie(y1, y2) = y;
  return MakeVec256(Vec128Xor(x1, y1), Vec128Xor(x2, y2));
}

inline Vec256 Vec256Load(const char *mem) {
  return std::make_tuple(Vec128Load(mem), Vec128Load(mem + 16));
}

}  // namespace aegis

}  // namespace security

#endif  // AEGIS_CIPHER_VEC256_TUPLES_H_
