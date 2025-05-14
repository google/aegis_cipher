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

#include "aegis128L.h"

#include "absl/strings/escaping.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>

#include <benchmark/benchmark.h>
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"

namespace security {

namespace aegis {

void BM_AEGIS128L_ASSOCIATE(benchmark::State& bs) {
  const size_t size = bs.range(0);
  Aegis128LState state;
  state.Reset(absl::HexStringToBytes("10010000000000000000000000000000"),
              absl::HexStringToBytes("10000200000000000000000000000000"));

  std::string payload(size, '0');
  for (auto s : bs) {
    state.AssociateData(payload);
  }
  bs.SetBytesProcessed(static_cast<int64_t>(bs.iterations()) * size);
}

void BM_AEGIS128L_ENCRYPT(benchmark::State& bs) {
  const size_t size = bs.range(0);
  Aegis128LState state;
  state.Reset(absl::HexStringToBytes("10010000000000000000000000000000"),
              absl::HexStringToBytes("10000200000000000000000000000000"));

  std::string payload(size, '0');
  std::unique_ptr<char[]> buffer{new char[size]};
  char* buf = buffer.get();
  for (auto s : bs) {
    state.Encrypt(payload, buf);
  }
  bs.SetBytesProcessed(static_cast<int64_t>(bs.iterations()) * size);
}

void BM_AEGIS128L_DECRYPT(benchmark::State& bs) {
  const size_t size = bs.range(0);
  Aegis128LState state;
  state.Reset(absl::HexStringToBytes("10010000000000000000000000000000"),
              absl::HexStringToBytes("10000200000000000000000000000000"));

  std::string payload(size, '0');
  std::unique_ptr<char[]> buffer{new char[size]};
  char* buf = buffer.get();
  for (auto s : bs) {
    state.Decrypt(payload, buf);
  }
  bs.SetBytesProcessed(static_cast<int64_t>(bs.iterations()) * size);
}

void BM_AEGIS128L_ENCRYPT_INPLACE(benchmark::State& bs) {
  const size_t size = bs.range(0);
  std::string key = absl::HexStringToBytes("00112233445566778899aabbccddeeff");
  std::string plaintext(size, '0');
  auto iv = absl::HexStringToBytes("10000200000000000000000000000000");
  Aegis128LState state;
  state.Reset(key, iv);
  for (auto s : bs) {
    state.Encrypt(plaintext.data(), size, plaintext.data());
  }
  bs.SetBytesProcessed(static_cast<int64_t>(bs.iterations()) * size);
}

void BM_AEGIS128L_RESET_AND_FINALIZE(benchmark::State& bs) {
  std::string key = absl::HexStringToBytes("00112233445566778899aabbccddeeff");
  auto iv = absl::HexStringToBytes("10000200000000000000000000000000");
  char tag[16];
  for (auto s : bs) {
    Aegis128LState state;
    state.Reset(key, iv);
    state.Finalize(tag);
  }
  bs.SetBytesProcessed(static_cast<int64_t>(bs.iterations()));
}

void BM_AEGIS128L_UNALIGNED(benchmark::State& bs) {
  // There is no real difference between AAD/Encrypt/Decrypt, so let's pick
  // Encrypt as representative case for cipher performance in the unaligned
  // data cases.
  BM_AEGIS128L_ENCRYPT(bs);
}

BENCHMARK(BM_AEGIS128L_ASSOCIATE)->Range(32, 1 << 27);
BENCHMARK(BM_AEGIS128L_ENCRYPT)->Range(32, 1 << 27);
BENCHMARK(BM_AEGIS128L_DECRYPT)->Range(32, 1 << 27);
BENCHMARK(BM_AEGIS128L_ENCRYPT_INPLACE)->Range(32, 1 << 27);

// Pick mostly primes here so that we always have many misalignments
// with 32 bytes.
BENCHMARK(BM_AEGIS128L_UNALIGNED)->Arg(1)->Arg(5)->Arg(23)->Arg(41)->Arg(57);

BENCHMARK(BM_AEGIS128L_RESET_AND_FINALIZE)->Arg(1);
}  // namespace aegis

}  // namespace security
