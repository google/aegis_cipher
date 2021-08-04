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

namespace security {

namespace aegis {

using internal::AegisStage, internal::DIRTY, internal::RESET, internal::AAD,
    internal::ENCRYPT, internal::DECRYPT, internal::FINALIZED,
    internal::VERIFIED;

namespace {

inline ABSL_ATTRIBUTE_ALWAYS_INLINE bool CompareTags(Aegis128LTag tag,
                                                     const char *expected_tag) {
  return Vec128Eq(tag, Vec128Load(expected_tag));
}

// This function determines if we can safely load "size" number of bytes from
// ptr. On Intel (and this file is pretty Intel specific already), we cannot
// cause a page-fault, unless we cross page boundaries. For instance, with 32
// bytes to not cross a page boundary, our 32-byte load must not start from the
// last 32 bytes of a page. We check this by (ptr & 0xfe0) != 0xfe0, which is
// only false for the range [0xfe1..0xfff], which amounts to what we want to
// check. This trick generalises to all "size" values that are a power of two.
//
// While we could also use a dynamic page_size other than 4k by using, e.g.
// sysconf(_SC_PAGE_SIZE), 4k is the most conservative choice, and hard-coding
// this value allows the compiler to generate imm instructions, which are much
// faster.
inline ABSL_ATTRIBUTE_ALWAYS_INLINE bool IsWideLoadSafe(const void *ptr,
                                                        size_t size) {
#if !defined(ADDRESS_SANITIZER) && !defined(MEMORY_SANITIZER) && \
    !defined(THREAD_SANITIZER)
#ifndef NDEBUG
  assert(!(size & (size - 1)));  // Power of two?
  assert(size < 128);          // Caller should use sane values.
#endif
  constexpr uint16_t kPageSize = 4096;
  uint16_t mask = kPageSize - size;
  return ((reinterpret_cast<uint64_t>(ptr) & mask) != mask);
#else
  // Sanitizers catches us accessing beyond the bounds of ptr, therefore we
  // disable wide loads in these cases.
  return false;
#endif
}

inline ABSL_ATTRIBUTE_ALWAYS_INLINE Aegis128LBlock MaskedLoad(const char *data,
                                                              size_t offset,
                                                              size_t size) {
#ifndef NDEBUG
  assert(size <= 32);
#endif
  const char *data_aligned = data - offset;
  if ((offset == 0 && size == 32) || IsWideLoadSafe(data_aligned, 32)) {
    return Vec256Load(data_aligned);
  }
  // We cannot do a full-load from the memory directly, as a 32-bytes wide load
  // might cause page-fault. We copy to scratch space and do a 32-byte load from
  // there.
  char tmp[32];
  memmove(tmp + offset, data, size);
  return Vec256Load(tmp);
}

void MaskedStore(Aegis128LBlock block, char *data, size_t offset, size_t size) {
#ifndef NDEBUG
  assert(size + offset <= 32);
#endif
  if (size == 0) {
    return;
  }
  if (size == 32) {
    Vec256Store(data, block);
    return;
  }

  char tmp[32];
  Vec256Store(tmp, block);
  memmove(data, tmp + offset, size);
}

const Vec128 mask_0x20_0x11 =
    MakeVec128Epi64x(0x201f1e1d1c1b1a19, 0x1817161514131211);
const Vec128 mask_0x10_0x01 =
    MakeVec128Epi64x(0x100f0e0d0c0b0a09, 0x0807060504030201);

// Constants from the AEGIS paper used in preparation of the IV
Vec128 const0() {
  return MakeVec128Epi64x(0x6279e99059372215, 0x0d08050302010100);
}
Vec128 const1() {
  return MakeVec128Epi64x(0xdd28b57342311120, 0xf12fc26d55183ddb);
}

inline ABSL_ATTRIBUTE_ALWAYS_INLINE Aegis128LBlock KeyStream(Vec128 S[8]) {
  Vec128 even = Vec128And(S[2], S[3]);
  even = Vec128Xor(Vec128Xor(S[1], S[6]), even);

  Vec128 odd = Vec128And(S[6], S[7]);
  odd = Vec128Xor(Vec128Xor(S[2], S[5]), odd);
  return MakeVec256(even, odd);
}

inline ABSL_ATTRIBUTE_ALWAYS_INLINE void StateUpdateRounds(Vec128 S[8],
                                                           Vec128 S0,
                                                           Vec128 S4) {
  Vec128 w = Vec128AesRound(S[7], S0);
  S[7] = Vec128AesRound(S[6], S[7]);
  S[6] = Vec128AesRound(S[5], S[6]);
  S[5] = Vec128AesRound(S[4], S[5]);
  S[4] = Vec128AesRound(S[3], S4);
  S[3] = Vec128AesRound(S[2], S[3]);
  S[2] = Vec128AesRound(S[1], S[2]);
  S[1] = Vec128AesRound(S[0], S[1]);
  S[0] = w;
}

inline ABSL_ATTRIBUTE_ALWAYS_INLINE void StateUpdate(Vec128 S[8],
                                                     Aegis128LBlock msg,
                                                     size_t offset,
                                                     size_t size) {
#ifndef NDEBUG
  assert(size + offset <= 32);
#endif
  Vec128 ma;
  Vec128 mb;

  std::tie(ma, mb) = msg;

  if (offset == 0) {
    StateUpdateRounds(S, S[0], S[4]);
  } else {
    Vec128 a = MakeVec128BroadcastEpi8(offset);
    Vec128 mask_a = Vec128CmpLtEpi8(a, mask_0x10_0x01);
    Vec128 mask_b = Vec128CmpLtEpi8(a, mask_0x20_0x11);
    ma = Vec128And(ma, mask_a);
    mb = Vec128And(mb, mask_b);
  }
  size_t end = size + offset;
  if (end != 32) {
    Vec128 a = MakeVec128BroadcastEpi8(end);
    Vec128 mask_a = Vec128CmpLtEpi8(a, mask_0x10_0x01);
    Vec128 mask_b = Vec128CmpLtEpi8(a, mask_0x20_0x11);
    ma = Vec128AndNot(mask_a, ma);
    mb = Vec128AndNot(mask_b, mb);
  }
  S[0] = Vec128Xor(ma, S[0]);
  S[4] = Vec128Xor(mb, S[4]);
}

}  // namespace

namespace internal {

inline ABSL_ATTRIBUTE_ALWAYS_INLINE void Initialize(Vec128 S[8], Vec128 key,
                                                    Vec128 iv) {
  S[0] = Vec128Xor(key, iv);
  S[1] = const1();
  S[2] = const0();
  S[3] = const1();
  S[4] = Vec128Xor(key, iv);
  S[5] = Vec128Xor(key, const0());
  S[6] = Vec128Xor(key, const1());
  S[7] = Vec128Xor(key, const0());
  Aegis128LBlock msg = MakeVec256(iv, key);
  for (int i = 0; i < 10; i++) {
    StateUpdate(S, msg, 0, 32);
  }
}

inline ABSL_ATTRIBUTE_ALWAYS_INLINE Vec128 Finalize(Vec128 S[8],
                                                    size_t aad_size_in_bytes,
                                                    size_t pt_size_in_bytes) {
  uint64_t aad_bits = 8 * aad_size_in_bytes;
  uint64_t pt_bits = 8 * pt_size_in_bytes;
  Vec128 tmp0 = MakeVec128Epi64x(pt_bits, aad_bits);
  Vec128 tmp = Vec128Xor(tmp0, S[2]);
  Aegis128LBlock msg = MakeVec256(tmp, tmp);
  for (int i = 0; i < 7; i++) {
    StateUpdate(S, msg, 0, 32);
  }
  Vec128 tag = Vec128Xor(S[0], S[1]);
  tag = Vec128Xor(tag, S[2]);
  tag = Vec128Xor(tag, S[3]);
  tag = Vec128Xor(tag, S[4]);
  tag = Vec128Xor(tag, S[5]);
  tag = Vec128Xor(tag, S[6]);
  // https://eprint.iacr.org/2013/695.pdf computes the tag as sum over S[0..7],
  // while http://competitions.cr.yp.to/round1/aegisv1.pdf computes the tag
  // over S[0..6]
  // tag = Vec128Xor(tag, S[7]);
  return tag;
}

// ProcessBlock<direction> unifies data processing across AAD/ENCRYPT/DECRYPT
// runs, and is instantiated inside of Process<direction>, and works as follows:
//
// direction == AAD    , update state from the input , don't store output.
// direction == ENCRYPT, update state from the input , store output.
// direction == DECRYPT, update state from the output, store output.
//

template <AegisStage direction>
// force inlining, as otherwise LLVM doesn't get the optimization in Process(..)
inline ABSL_ATTRIBUTE_ALWAYS_INLINE void ProcessBlock(
    ResumableState *__restrict rs, const char *input, char *output,
    size_t offset, size_t size) {
#ifndef NDEBUG
  assert(offset < 32);
#endif
  /* This function is designed to completely be inlined including all the
     padding helpers. Those padding helpers are designed with bounds checking
     that can be optimized away when size is known at compile time.

     The intuition for the padding helpers are that they only opperate on the
     input up to n-th byte as given by the "size" argument, and will do nothing
     after that byte or assume zeros. */

  if (!size) {
    return;
  }

  Aegis128LBlock in_block = MaskedLoad(input, offset, size);
  if (direction == AAD) {
    StateUpdate(rs->S, in_block, offset, size);
  } else if (direction == ENCRYPT || direction == DECRYPT) {
    // We resume a partial-block, the key-stream is stored in S[8]/S[9].
    Aegis128LBlock key_stream =
        offset ? MakeVec256(rs->S[8], rs->S[9]) : KeyStream(rs->S);
    Aegis128LBlock out_block = Vec256Xor(in_block, key_stream);
    MaskedStore(out_block, output, offset, size);
    StateUpdate(rs->S, direction == ENCRYPT ? in_block : out_block, offset,
                size);
    if (offset + size != 32) {
      // We did not complete a block, store the key-stream in S[8]/S[9], so when
      // we pick up processing this partial block, the key-stream is available.
      rs->S[8] = std::get<0>(key_stream);
      rs->S[9] = std::get<1>(key_stream);
    }
  }
}

template <AegisStage direction>
inline ABSL_ATTRIBUTE_ALWAYS_INLINE void Process(
    ResumableState *__restrict__ rs, const char *input, char *output,
    size_t previous_block_offset, size_t size) {
#ifndef NDEBUG
  assert(previous_block_offset < 32);
#endif

  /* This function processes the input mostly in 32-byte chunks. However, it
     also has to take care of any incomplete blocks from its last invocation
     (indicated by a non-zero previous_block_offset) and also has to partially
     process a block, if processing does not end on a block boundary. As
     ProcessBlock is designed to be inlined here, the loop in this function does
     the heavy-lifting. */

  if (previous_block_offset) {
    size_t bytes_left_in_previous_block = 32 - previous_block_offset;
    if (size <= bytes_left_in_previous_block) {
      ProcessBlock<direction>(rs, input, output, previous_block_offset, size);
      // No more processing necessary.
      return;
    } else {
      ProcessBlock<direction>(rs, input, output, previous_block_offset,
                              bytes_left_in_previous_block);
      input += bytes_left_in_previous_block;
      output += bytes_left_in_previous_block;
      size -= bytes_left_in_previous_block;
    }
  }

  size_t full_blocks = size / 16;
  size_t i = 0;
// Unroll this loop twice, as this seems to give better vectorization for AES
// instructions.
#pragma unroll(2)
  for (; i + 1 < full_blocks; i += 2) {
    // Calling ProcessBlock with a fixed size=32, removes its bounds checks.
    ProcessBlock<direction>(rs, input + i * 16, output + i * 16, 0, 32);
  }
  ProcessBlock<direction>(rs, input + i * 16, output + i * 16, 0, size % 32);
}

}  // namespace internal

Aegis128LPreKeyed::Aegis128LPreKeyed(absl::string_view key,
                                     std::function<Aegis128LNonce()> get_nonce)
    : key_(Vec128Load(key.data())), get_nonce_(get_nonce) {
  assert(key.size() == 16);
}

void Aegis128LPreKeyed::Encrypt(absl::string_view plaintext,
                                absl::string_view aad,
                                std::string *ciphertext) {
  // So far we use a 16 byte IV and a 16 byte tag.
  const size_t kIvSize = 16;
  const size_t kTagSize = 16;
  size_t ciphertext_size = plaintext.size() + kIvSize + kTagSize;
  ciphertext->resize(ciphertext_size);
  char *buffer = &(*ciphertext)[0];
  Aegis128LNonce nonce = get_nonce_();
  Vec128Store(buffer, nonce);
  Aegis128LState state;
  state.Reset(key_, nonce);
  state.AssociateData(aad);
  state.Encrypt(plaintext, buffer + kIvSize);
  state.Finalize(&buffer[ciphertext_size - 16]);
}

bool Aegis128LPreKeyed::Decrypt(absl::string_view ciphertext,
                                absl::string_view aad, std::string *plaintext) {
  const size_t kIvSize = 16;
  const size_t kTagSize = 16;
  if (ciphertext.size() < kIvSize + kTagSize) {
    return false;
  }
  Aegis128LNonce iv = LoadNonce(&ciphertext[0]);
  size_t plaintext_size = ciphertext.size() - kIvSize - kTagSize;

  Aegis128LState state;
  state.Reset(key_, iv);
  state.AssociateData(aad);
  absl::string_view raw_ciphertext(&ciphertext[kIvSize], plaintext_size);
  plaintext->resize(plaintext_size);
  state.Decrypt(raw_ciphertext, &(*plaintext)[0]);
  return state.Verify(&ciphertext[ciphertext.size() - kTagSize], [&]() {
    // We are free to clear plaintext, as the contract with the caller is that
    // we are free to override this string.
    memset(&(*plaintext)[0], 0, plaintext_size);
    plaintext->resize(0);
  });
}

void Aegis128LState::Reset(Aegis128LKey key, Aegis128LNonce iv) {
  CheckStage(RESET, {DIRTY, RESET, AAD, ENCRYPT, DECRYPT, FINALIZED, VERIFIED});
  aad_size_ = 0;
  payload_size_ = 0;
  internal::Initialize(rs_.S, key, iv);
}

void Aegis128LState::AssociateData(const char *aad, size_t s) {
  CheckStage(AAD, {RESET, AAD});
  internal::Process<AAD>(&rs_, aad, nullptr, aad_size_ % 32, s);
  aad_size_ += s;
}

void Aegis128LState::Encrypt(const char *plaintext, size_t s,
                             char *ciphertext) {
  CheckStage(ENCRYPT, {RESET, AAD, ENCRYPT});
  internal::Process<ENCRYPT>(&rs_, plaintext, ciphertext, payload_size_ % 32,
                             s);
  payload_size_ += s;
}

void Aegis128LState::Decrypt(const char *ciphertext, size_t s,
                             char *plaintext) {
  CheckStage(DECRYPT, {RESET, AAD, DECRYPT});
  internal::Process<DECRYPT>(&rs_, ciphertext, plaintext, payload_size_ % 32,
                             s);
  payload_size_ += s;
}

Aegis128LTag Aegis128LState::Finalize() {
  CheckStage(internal::FINALIZED,
             {internal::RESET, internal::AAD, internal::ENCRYPT});
  return internal::Finalize(rs_.S, aad_size_, payload_size_);
}

bool Aegis128LState::Verify(const char *expected_tag,
                            absl::FunctionRef<void()> destroy_buffer) {
  CheckStage(internal::VERIFIED,
             {internal::RESET, internal::AAD, internal::DECRYPT});
  Aegis128LTag tag = internal::Finalize(rs_.S, aad_size_, payload_size_);
  if (!CompareTags(tag, expected_tag)) {
    destroy_buffer();
    return false;
  }
  return true;
}

}  // namespace aegis

}  // namespace security
