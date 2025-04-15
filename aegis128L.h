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

#ifndef AEGIS_CIPHER_AEGIS128L_H_
#define AEGIS_CIPHER_AEGIS128L_H_

#include "absl/functional/function_ref.h"
#include "absl/numeric/bits.h"
#include "absl/strings/string_view.h"
#include "vec128.h"
#include "vec256_tuples.h"

namespace security {

namespace aegis {

typedef Vec256 Aegis128LBlock;
typedef Vec128 Aegis128LTag;
typedef Vec128 Aegis128LNonce;
typedef Vec128 Aegis128LKey;

namespace internal {

enum AegisStage {
  DIRTY = 0,
  RESET,
  AAD,
  ENCRYPT,
  DECRYPT,
  FINALIZED,
  VERIFIED
};

struct ResumableState final {
  // S[0..7] is the internal state S as defined in the AEGIS paper.
  // S[8..9] might be used for the key stream when we process a partial block.

  // When we start a fresh block, we extract the key stream from S[0..7] and
  // update S[0..7]. When we find that the input does not cover a full block, we
  // save the key stream in S[8..9] and use that in the next invocation.

  // NOLINTNEXTLINE
  alignas(128) Vec128 S[10];
};

inline uint64_t LittleEndianFromHost64(uint64_t v) {
  if constexpr (absl::endian::native != absl::endian::little) {
    v = absl::byteswap(v);
  }
  return v;
}

}  // namespace internal

inline Aegis128LKey LoadKey(const char *key) { return Vec128Load(key); }

inline Aegis128LKey LoadKey(absl::string_view key) {
  assert(key.size() == 16);
  return Vec128Load(key.data());
}

inline Aegis128LNonce LoadNonce(const char *nonce) { return Vec128Load(nonce); }

inline Aegis128LNonce LoadNonce(absl::string_view nonce) {
  assert(nonce.size() == 16);
  return Vec128Load(nonce.data());
}

// Load nonce from two numbers with n0 being the first part, and n1 being the
// second. The nonce parts are assumed to be in little-endian ordering.
inline Aegis128LNonce LoadNonceLE(uint64_t n1, uint64_t n0) {
  // While it is not particularly useful to have LittleEndianFromHost64
  // conversions in heavily Intel focused code, it reminds us that we expected
  // n1 & n0 to be in little-endian.
  return MakeVec128Epi64x(internal::LittleEndianFromHost64(n1),
                          internal::LittleEndianFromHost64(n0));
}

class Aegis128LPreKeyed final {
 public:
  // Aegis128LPreKeyed is a convience class for one-shot encryption and
  // decryption. Users must supply their own nonce generator and must take care
  // that nonces are not repeated in the context of a key. For instance, using a
  // a simple counter is not safe, when the key is shared between multiple
  // encrypting processes. We recommend to use a cryptographically secure random
  // generator to generate nonces.
  explicit Aegis128LPreKeyed(absl::string_view key,
                             std::function<Aegis128LNonce()> get_nonce);
  // Directly encrypts to ciphertext.
  // ciphertext must not overlap with plaintext and aad.
  void Encrypt(absl::string_view plaintext, absl::string_view aad,
               std::string *ciphertext);

  // Directly decrypts to plaintext.
  // plaintext must not overlap with ciphertext and aad.
  //
  // Returns false when the tag verification fails.
  bool Decrypt(absl::string_view ciphertext, absl::string_view aad,
               std::string *plaintext);

 protected:
  friend class Aegis128LTest;

 private:
  const Aegis128LKey key_;
  std::function<Aegis128LNonce()> get_nonce_;
};

class Aegis128LState final {
 public:
  // Aegis128LState is a low-level API that provides a streaming API for the
  // AEGIS128L cipher. Please read the documentation here in full to avoid
  // introducing vulnerabilities.
  //
  // Aegis128LState represents the Aegis AEAD cipher state. It must be Reset to
  // a key and an IV before use.
  //
  // ENCRYPTION: For encryption we expect the following call sequence:
  //   Reset{1}->AssociateData{0,m} -> Encrypt{0,n} -> Finalize{1}
  // where AssociateData is called between 0 and m times, Encrypt is
  // called n times, and Finalize is called exactly once.
  //
  // DECRYPTION: For decryption we expect the following call sequence:
  //   Reset{1}->AssociateData{0,m} -> Decrypt{0,n} -> Verify{1}
  // where AssociateData is called between 0 and m times, Decrypt is
  // called n times, and Verify is called exactly once.
  //
  // The Decrypt operation is generally safe, when the output is buffered and
  // released to further processing ONLY after the Verify operation has
  // successfully verified the cryptographic tag. If Verify fails, you MUST
  // destroy the buffered output, and you MUST do so in the destroy_buffer
  // callback handed to Verify. It is best to sanitize the buffer by memsetting
  // the content to zero.
  //
  // We generally advise to not do any interpretation of the decryption output
  // before calling Verify. If you do so, an attacker can feed modified
  // ciphertext to you, and then guess the plaintext content based on a
  // timing-side channel. Such a side-channel would allow an attacker to
  // reconstruct the internal state of Aegis128L and allow forgery attacks.
  //
  // Aegis128LState state;
  // state.Reset(key, iv);
  //
  // state.AssociateData(aad_1);
  // state.AssociateData(aad_2);
  // ...
  // state.AssociateData(aad_m);
  //
  // state.Decrypt(cipher_1, plain_1);
  // state.Decrypt(cipher_2, plain_2);
  // ...
  // state.Decrypt(cipher_n, plain_n);
  //
  // state.Verify(
  //    tag,
  //    [plain_1, ..., plain_n] () {
  //    memset(plain_1, 0, sizeof(plain_1));
  //    ..
  //    memset(plain_n, 0, sizeof(plain_n));
  // });
  //
  Aegis128LState() {}
  inline ~Aegis128LState() {
    // Scrub cipher state before freeing this object.
    memset(&rs_, 0, sizeof(internal::ResumableState));
    __asm__ __volatile__("" : : "r"(&rs_) : "memory");
  }

  // Explicitly disallow copying. There is no case where this can be argued to
  // be necessary as we never want reuse another state because all states are
  // bound to a nonce, which we never want to reuse. Use the default constructor
  // and Reset instead.
  Aegis128LState(const Aegis128LState &) = delete;
  Aegis128LState &operator=(const Aegis128LState &) = delete;

  void Reset(Aegis128LKey key, Aegis128LNonce iv);
  void Reset(absl::string_view key, absl::string_view iv) {
    Reset(LoadKey(key), LoadNonce(iv));
  }

  // Adds associated data.
  void AssociateData(const char *aad, size_t s);
  void AssociateData(absl::string_view aad) {
    AssociateData(aad.data(), aad.size());
  }

  // Encrypts plaintext into ciphertext. ciphertext needs to be able to hold
  // plaintext.size() bytes.
  void Encrypt(const char *plaintext, size_t s, char *ciphertext);
  void Encrypt(absl::string_view plaintext, char *ciphertext) {
      Encrypt(plaintext.data(), plaintext.size(), ciphertext);
  }

  // Decrypt ciphertext into plaintext. plaintext needs to be able to hold
  // ciphertext.size() bytes.
  void Decrypt(const char *ciphertext, size_t s, char *plaintext);
  void Decrypt(absl::string_view ciphertext, char *plaintext) {
    Decrypt(ciphertext.data(), ciphertext.size(), plaintext);
  }

  void Finalize(char *tag) {
    Aegis128LTag generated_tag = Finalize();
    Vec128Store(tag, generated_tag);
  }

  // Finalizes the Aegis state and checks the result against tag.  The caller
  // needs to provide a destruction function such that all buffers produced by
  // previous calls to Decrypt are destroyed. Please read the class
  // documentation on how to implement destroy_buffer.
  bool Verify(const char *expected_tag, absl::FunctionRef<void()> destroy_buffer);

 protected:
  friend class Aegis128LTest;

 private:
  internal::ResumableState rs_;
  size_t aad_size_;
  size_t payload_size_;
#ifndef NDEBUG
  void CheckStage(internal::AegisStage current_stage,
                  std::initializer_list<internal::AegisStage> allowed_stages) {
    assert(std::find(std::begin(allowed_stages), std::end(allowed_stages),
                     stage_) != std::end(allowed_stages));
    stage_ = current_stage;
  }
  internal::AegisStage stage_ = internal::DIRTY;
#else
  void CheckStage(internal::AegisStage current_stage,
                  std::initializer_list<internal::AegisStage> allowed_stages) { }
#endif

  // Produces Aegis tag.
  Aegis128LTag Finalize();
};

}  // namespace aegis

}  // namespace security

#endif  // AEGIS_CIPHER_AEGIS128L_H_
