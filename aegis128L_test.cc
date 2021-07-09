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

#ifdef __SSE2__
#ifdef __AES__

#include <emmintrin.h>  // SSE2
#include <wmmintrin.h>  // AES_NI instructions.
#include <xmmintrin.h>  // Datatype __mm128i

#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>

#include "gtest/gtest.h"
#include "absl/numeric/int128.h"
#include "absl/strings/string_view.h"
#include "jsoncpp/json/reader.h"

namespace security {

namespace aegis {

using internal::AegisStage, internal::DIRTY, internal::RESET, internal::AAD,
    internal::ENCRYPT, internal::DECRYPT, internal::FINALIZED,
    internal::VERIFIED;

// Short list of test vectors.
// The WycheproofTest below uses a much longer list.
struct TestVector {
  std::string key;
  std::string iv;
  std::string plaintext;  // hex encoded plaintext
  std::string a_data;
  std::string raw_ciphertext;  // hex encoded raw ciphertext (no IV, no tag)
  std::string tag;
};

Aegis128LNonce CounterNonce() {
  static std::atomic<absl::uint128> ctr = absl::uint128(0);
  absl::uint128 next = ctr.load();
  while (!ctr.compare_exchange_weak(next, next + 1, std::memory_order_relaxed,
                                    std::memory_order_relaxed)) {
  };
  return _mm_set_epi64x(Uint128Low64(next), Uint128High64(next));
}

std::vector<TestVector>* test_vectors = new std::vector<TestVector>({{
    // Test vector adjusted the case where the tag as sum over S[0] .. S[6]
    {"00000000000000000000000000000000", "00000000000000000000000000000000",
     "00000000000000000000000000000000", "", "41de9000a7b5e40e2d68bb64d99ebb19",
     "f4d997cc9b94227ada4fe4165422b1c8"},
    {"00000000000000000000000000000000", "00000000000000000000000000000000",
     "00000000000000000000000000000000", "00000000000000000000000000000000",
     "29a0ce1f5dce8c404d56d00491668604", "29c9d93afd7e1276112a1fd0c344ccd2"},
    {"00010000000000000000000000000000", "00000200000000000000000000000000",
     "00000000000000000000000000000000", "00010203",
     "1c0f229f289844def2c1ef28bea0abf0", "1f0799d68840d2364e7eeca6d41b4d05"},
    {"10010000000000000000000000000000", "10000200000000000000000000000000",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "0001020304050607",
     "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
     "cc6f3372f6aa1bb82388d695c3962d9a"},
    // Test vectors from the CAESAR competition
    {"55565758595A5B5C5D5E5F6061626364", "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF", "",
     "", "", "439ef345a332a4f83c9cc28debea9be0"},
    {"55565758595A5B5C5D5E5F6061626364", "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF", "",
     "A0", "", "a2694bd5658385c137048077018c0a69"},
    // Test cases generated by the implementation itself
    {"10010000000000000000000000000000", "10000200000000000000000000000000",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "",
     "c1c1e788dd160668e3a9054030ce5741d02556d1c6c35ce2dcd860c28c303c19",
     "807df2b3aacd5f944f589b6e3d897113"},
    {"00010000000000000000000000000000", "00000200000000000000000000000000", "",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "",
     "e5a4d7f0ffb051868dd94fb7438d9949"},
    {"00010000000000000000000000000000", "00000200000000000000000000000000",
     "0101", "", "22f6", "a57f182297e44c2788ea1ae8c216e482"},
}});

class Aegis128LTest : public testing::Test {
 public:
  static std::string m128i2Hex(__m128i value) {
    char bytes[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes), value);
    return absl::BytesToHexString(absl::string_view(bytes, 16));
  }

  static __m128i Hex2m128i(absl::string_view hex) {
    std::string val = absl::HexStringToBytes(hex);
    assert(16 == val.size());
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(val.data()));
  }

  static void CleanseNonSensitiveStateFields(Aegis128LState* state) {
    // Additionally cleanse non-sensitive fields of Aegis128LState that its
    // destructor does not override.
    state->aad_size_ = state->payload_size_ = 0;
#ifndef NDEBUG
    state->stage_ = internal::DIRTY;
#endif
  }

  static bool EncryptHex(const std::string& key_hex, const std::string& iv_hex,
                         const std::string& aad_hex,
                         const std::string& plaintext_hex,
                         std::string* raw_ciphertext_hex,
                         std::string* tag_hex) {
    Aegis128LKey key = Hex2m128i(key_hex);
    Aegis128LNonce iv = Hex2m128i(iv_hex);
    std::string plaintext = absl::HexStringToBytes(plaintext_hex);
    std::string aad = absl::HexStringToBytes(aad_hex);
    std::unique_ptr<char[]> buffer(new char[plaintext.size()]);
    Aegis128LTag tag;
    Aegis128LState state;
    state.Reset(key, iv);
    state.AssociateData(aad);
    state.Encrypt(plaintext, buffer.get());
    state.Finalize(&tag);
    *raw_ciphertext_hex = absl::BytesToHexString(
        absl::string_view(buffer.get(), plaintext.size()));
    *tag_hex = m128i2Hex(tag);
    return true;
  }

  static bool DecryptHex(const std::string& key_hex, const std::string& iv_hex,
                         const std::string& aad_hex,
                         const std::string& ciphertext_hex,
                         const std::string& tag_hex,
                         std::string* plaintext_hex) {
    Aegis128LPreKeyed cipher(absl::HexStringToBytes(key_hex), CounterNonce);
    std::string ct = absl::HexStringToBytes(iv_hex + ciphertext_hex + tag_hex);
    std::string pt;
    bool ok = cipher.Decrypt(ct, absl::HexStringToBytes(aad_hex), &pt);
    if (ok) {
      *plaintext_hex = absl::BytesToHexString(pt);
    }
    return ok;
  }

  static std::string KeyHex(const Aegis128LPreKeyed& cipher) {
    return m128i2Hex(cipher.key_);
  }
  static void ForceStage(Aegis128LState* state, AegisStage forced_stage) {
#ifndef NDEBUG
    state->stage_ = forced_stage;
#endif
  }

  static bool WycheproofTest(const Json::Value& root) {
    int correct_encryptions = 0;
    int correct_decryptions = 0;
    for (const Json::Value& test_group : root["testGroups"]) {
      for (const Json::Value& test : test_group["tests"]) {
        std::string comment = test["comment"].asString();
        // All values below are hexadecimal.
        std::string key = test["key"].asString();
        std::string iv = test["iv"].asString();
        std::string msg = test["msg"].asString();
        std::string ct = test["ct"].asString();
        std::string aad = test["aad"].asString();
        std::string tag = test["tag"].asString();
        std::string id = test["tcId"].asString();
        std::string expected = test["result"].asString();
        std::string encrypted;
        std::string tag2;

        bool success = EncryptHex(key, iv, aad, msg, &encrypted, &tag2);
        if (success) {
          if (encrypted + tag2 == ct + tag) {
            if (expected == "invalid") {
              // There are essentially two ways to get here:
              // (1) using an old version of the algorithm,
              // (2) encrypting with invalid parameters such as wrong IV size.
              ADD_FAILURE() << "invalid encryption:" << id;
            } else {
              ++correct_encryptions;
            }
          } else {
            if (expected == "invalid") {
              // Getting here is completely acceptable.
              // Invalid test vectors are typically test vectors with an
              // incorrect ciphertext. Trying to reencrypt just gives the
              // correct ciphertext and does not detect the broken ciphertext.
              ++correct_encryptions;
            } else {
              ADD_FAILURE() << "Incorrect encryption:" << id
                            << " encrypted:" << (encrypted + tag2)
                            << " expected: " << (ct + tag);
            }
          }
        } else {
          if (expected == "valid") {
            ADD_FAILURE() << "could not encrypt test with tcId:" << id;
          } else {
            ++correct_encryptions;
          }
        }

        std::string decrypted;
        success = DecryptHex(key, iv, aad, ct, tag, &decrypted);
        if (success) {
          if (expected == "invalid") {
            ADD_FAILURE() << "decrypted invalid ciphertext:" << id;
          } else if (msg == decrypted) {
            ++correct_decryptions;
          } else {
            ADD_FAILURE() << "Incorrect decryption:" << id;
          }
        } else {
          if (expected == "valid") {
            ADD_FAILURE() << "Could not decrypt test with tcId:" << id;
          } else {
            ++correct_decryptions;
          }
        }
      }
    }
    int num_tests = root["numberOfTests"].asInt();
    testing::Message summary;
    summary << root["algorithm"].asString() << "\n";
    summary << root["generatorVersion"].asString() << "\n";
    summary << "total number of tests: " << num_tests << "\n";
    summary << "correct encryptions:" << correct_encryptions << "\n";
    summary << "correct decryptions:" << correct_decryptions << "\n";
    std::cout << summary;
    return (correct_encryptions == num_tests) &&
           (correct_decryptions == num_tests);
  }
};

TEST_F(Aegis128LTest, EncryptDecrypt) {
  size_t kMaxSize = 200;
  Aegis128LPreKeyed cipher("0123456789abcdef", CounterNonce);
  std::string pt = "c";
  for (int i = 0; i <= kMaxSize; i++) {
    std::string ct;
    std::string decrypted;
    cipher.Encrypt(pt, "", &ct);
    EXPECT_TRUE(cipher.Decrypt(ct, "", &decrypted))
        << "i:" << i << "pt:" << absl::BytesToHexString(pt)
        << "ct:" << absl::BytesToHexString(ct);
    EXPECT_EQ(absl::BytesToHexString(pt), absl::BytesToHexString(decrypted))
        << "i:" << i << "ct:" << absl::BytesToHexString(ct);
    pt += "x";
  }
}

TEST_F(Aegis128LTest, EncryptOnce) {
  Aegis128LPreKeyed cipher("0123456789abcdef", CounterNonce);
  std::string ct;
  std::string tag;
  std::string hex = "0123456789abcdef0123456789abcdef";
  EncryptHex(hex, hex, hex, hex, &ct, &tag);
  EXPECT_EQ(ct, "805d62213434b2532548ff9901c61883");
  EXPECT_EQ(tag, "ea7cf897a74132ddb2df35c754d3388c");
}

TEST_F(Aegis128LTest, EncryptDecryptWithAAD) {
  size_t kMaxSize = 200;
  Aegis128LPreKeyed cipher("0123456789abcdef", CounterNonce);
  std::string pt = "";
  std::string aad = "";
  for (int i = 0; i <= kMaxSize; i++) {
    std::string ct;
    std::string decrypted;
    cipher.Encrypt(pt, aad, &ct);
    EXPECT_TRUE(cipher.Decrypt(ct, aad, &decrypted))
        << "i:" << i << "pt:" << absl::BytesToHexString(pt)
        << "ct:" << absl::BytesToHexString(ct);
    EXPECT_EQ(absl::BytesToHexString(pt), absl::BytesToHexString(decrypted))
        << "i:" << i << "ct:" << absl::BytesToHexString(ct);
    pt += "x";
    aad += "y";
  }
}

TEST_F(Aegis128LTest, TestVectorsEncrypt) {
  for (const TestVector& v : *test_vectors) {
    std::string raw_ciphertext;
    std::string tag;
    bool ok =
        EncryptHex(v.key, v.iv, v.a_data, v.plaintext, &raw_ciphertext, &tag);
    ASSERT_TRUE(ok);
    EXPECT_EQ(v.raw_ciphertext, raw_ciphertext);
    EXPECT_EQ(v.tag, tag);
  }
}

TEST_F(Aegis128LTest, TestVectorsDecrypt) {
  for (const TestVector& v : *test_vectors) {
    Aegis128LPreKeyed cipher(absl::HexStringToBytes(v.key), CounterNonce);
    std::string ct = absl::HexStringToBytes(v.iv + v.raw_ciphertext + v.tag);
    std::string aad = absl::HexStringToBytes(v.a_data);
    std::string decrypted;
    EXPECT_TRUE(cipher.Decrypt(ct, aad, &decrypted));
    EXPECT_EQ(v.plaintext, absl::BytesToHexString(decrypted));
  }
}

static std::unique_ptr<Json::Value> ReadJsonFile(const std::string& filename) {
  const std::string kTestVectors = "./";
  std::ifstream input;
  input.open(kTestVectors + filename);
  std::unique_ptr<Json::Value> root(new Json::Value);
  input >> (*root);
  return root;
}

TEST_F(Aegis128LTest, TestVectors) {
  std::unique_ptr<Json::Value> root = ReadJsonFile("aegis128L_test.json");
  ASSERT_TRUE(WycheproofTest(*root));
}

TEST_F(Aegis128LTest, FinalizeAPI) {
  std::string key_hex = "10010000000000000000000000000000";
  std::string iv_hex = "10000200000000000000000000000000";
  std::string key = absl::HexStringToBytes(key_hex);
  std::string iv = absl::HexStringToBytes(iv_hex);

  Aegis128LState state;
  state.Reset(key, iv);
  Aegis128LTag tag;
  state.Finalize(&tag);

  Aegis128LState state2;
  state2.Reset(key, iv);
  char tag2[16];
  state2.Finalize(tag2);

  Aegis128LState state3;
  state3.Reset(key, iv);
  Aegis128LTag tag3 = state3.Finalize();

  // Verify that all finalize APIs return the same result.
  ASSERT_EQ(std::memcmp(reinterpret_cast<char*>(&tag), tag2, 16), 0);
  ASSERT_EQ(std::memcmp(reinterpret_cast<char*>(&tag), &tag3, 16), 0);
}

TEST_F(Aegis128LTest, IncrementalUpdate) {
  std::string key_hex = "10010000000000000000000000000000";
  std::string iv_hex = "10000200000000000000000000000000";
  std::string key = absl::HexStringToBytes(key_hex);
  std::string iv = absl::HexStringToBytes(iv_hex);
  Aegis128LState state;
  state.Reset(key, iv);

  std::string aad_hex = "";
  std::string aad_parts[] = {"00010203", "04050607"};
  for (const std::string& p : aad_parts) {
    aad_hex.append(p);
    state.AssociateData(absl::HexStringToBytes(p));
  }

  std::string plaintext_hex = "";
  std::string plaintext_parts[] = {"79d94593d8c2119d7e8fd9b8fc77845c5c",
                                   "077a05b2528b6ac54b563a", "ed8efe84"};
  std::string ciphertext_hex = "";
  for (const std::string& p_hex : plaintext_parts) {
    plaintext_hex.append(p_hex);
    std::string p = absl::HexStringToBytes(p_hex);
    std::unique_ptr<char[]> ciphertext_buffer(new char[p.size()]);
    state.Encrypt(p, ciphertext_buffer.get());
    ciphertext_hex.append(absl::BytesToHexString(
        absl::string_view(ciphertext_buffer.get(), p.size())));
  }

  Aegis128LTag tag;
  state.Finalize(&tag);

  std::string raw_ciphertext_hex;
  std::string tag_hex;
  EncryptHex(key_hex, iv_hex, aad_hex, plaintext_hex, &raw_ciphertext_hex,
             &tag_hex);
  ASSERT_EQ(m128i2Hex(tag), tag_hex);
  ASSERT_EQ(raw_ciphertext_hex, ciphertext_hex);

  // Decrypt
  Aegis128LState dec_state;
  dec_state.Reset(key, iv);
  for (const std::string& p : aad_parts) {
    dec_state.AssociateData(absl::HexStringToBytes(p));
  }
  std::string raw_ciphertext = absl::HexStringToBytes(raw_ciphertext_hex);
  std::unique_ptr<char[]> plaintext_buffer(new char[raw_ciphertext.size()]);
  dec_state.Decrypt(raw_ciphertext, plaintext_buffer.get());
  Aegis128LTag dec_tag;

  // We force the last operation to be "ENCRYPT" so that we can call
  // dec_state.Finalize. Usually callers should call .Verify, but we would like
  // to do a hex comparison, which is an absolutely silly idea outside of test
  // cases.
  ForceStage(&dec_state, ENCRYPT);

  dec_state.Finalize(&dec_tag);
  ASSERT_EQ(m128i2Hex(dec_tag), tag_hex);
  ASSERT_EQ(plaintext_hex, absl::BytesToHexString(absl::string_view(
                               plaintext_buffer.get(), raw_ciphertext.size())));
}

// Same as above, but try every segmentation of aad and msg into 3 parts.
TEST_F(Aegis128LTest, IncrementalUpdate2) {
  std::string key_hex = "00112233445566778899aabbccddeeff";
  std::string iv_hex = "000102030405060708090a0b0c0d0e0f";
  std::string key = absl::HexStringToBytes(key_hex);
  std::string iv = absl::HexStringToBytes(iv_hex);
  std::string aad = absl::HexStringToBytes(
      "011112131415161718191a1b1c1d1e1f20212223242526272829871237319732"
      "8917398749812378123714198238213821381471237123712837128319371831"
      "9129398419823981249812731419827398124798173981239812398172381231"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "198731982471982739813982147981249821381238217128371231982321412a");
  std::string msg = absl::HexStringToBytes(
      "0001020817989879812798174981291786418764187623871637727374838382"
      "9817249812749812749184719827198471982731986378163789821718931121"
      "8172987219739857982173198231982739817398149814918479812888888888"
      "198274981723987149abcdef28319827498131aadf798gg31739817398173198"
      "9871237981247978980000000000478124877182841238174982139812123213"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "9812398747123817248123123213123124879918288749812738213812372312");
  Aegis128LState ref;
  ref.Reset(key, iv);
  ref.AssociateData(aad);
  std::unique_ptr<char[]> expected(new char[msg.size()]);
  ref.Encrypt(msg, expected.get());
  std::string expected_hex =
      absl::BytesToHexString(absl::string_view(expected.get(), msg.size()));
  Aegis128LTag expected_tag;
  ref.Finalize(&expected_tag);

  // Incremental update of aad
  for (int s1 = 0; s1 <= aad.size(); s1++) {
    for (int s2 = s1; s2 <= aad.size(); s2++) {
      std::string aad1(aad, 0, s1);
      std::string aad2(aad, s1, s2 - s1);
      std::string aad3(aad, s2, aad.size() - s2);
      Aegis128LState state;
      state.Reset(key, iv);
      state.AssociateData(aad1);
      state.AssociateData(aad2);
      state.AssociateData(aad3);
      std::unique_ptr<char[]> ct(new char[msg.size()]);
      memset(&ct[0], 0xff, msg.size());
      state.Encrypt(msg, ct.get());
      Aegis128LTag tag;
      state.Finalize(&tag);
      ASSERT_EQ(m128i2Hex(expected_tag), m128i2Hex(tag))
          << "s1:" << s1 << " s2:" << s2;
    }
  }
  // Incremental update of msg
  for (int s1 = 0; s1 <= msg.size(); s1++) {
    for (int s2 = s1; s2 <= msg.size(); s2++) {
      std::string m1(msg, 0, s1);
      std::string m2(msg, s1, s2 - s1);
      std::string m3(msg, s2, msg.size() - s2);
      Aegis128LState state;
      state.Reset(key, iv);
      state.AssociateData(aad);
      std::unique_ptr<char[]> ct(new char[msg.size()]);
      memset(&ct[0], 0xff, msg.size());
      state.Encrypt(m1, ct.get());
      state.Encrypt(m2, ct.get() + s1);
      state.Encrypt(m3, ct.get() + s2);
      Aegis128LTag tag;
      state.Finalize(&tag);
      ASSERT_EQ(m128i2Hex(expected_tag), m128i2Hex(tag))
          << "s1:" << s1 << " s2:" << s2;
      std::string ct_hex =
          absl::BytesToHexString(absl::string_view(ct.get(), msg.size()));
      ASSERT_EQ(expected_hex, ct_hex) << "s1:" << s1 << " s2:" << s2;
    }
  }
}

TEST_F(Aegis128LTest, NonceAPIEquality) {
  std::string key_hex = "10010000000000000000000000000000";
  std::string key = absl::HexStringToBytes(key_hex);

  Aegis128LState state1;
  state1.Reset(
      LoadKey(key),
      LoadNonce(absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f")));
  Aegis128LTag tag1;
  state1.Finalize(&tag1);

  Aegis128LState state2;
  state2.Reset(LoadKey(key),
               LoadNonceLE(0x0f0e0d0c0b0a0908, 0x0706050403020100));
  Aegis128LTag tag2;
  state2.Finalize(&tag2);

  // Verify both nonce APIs return the same result.
  ASSERT_EQ(std::memcmp(reinterpret_cast<char*>(&tag1),
                        reinterpret_cast<char*>(&tag2), 16),
            0);
}

TEST_F(Aegis128LTest, ScrubbingState) {
  std::string key_hex = "10010000000000000000000000000000";
  std::string key = absl::HexStringToBytes(key_hex);

  alignas(Aegis128LState) char backing[sizeof(Aegis128LState)];
  memset(backing, 0, sizeof(Aegis128LState));

  Aegis128LState* state = new (backing) Aegis128LState();
  state->Reset(
      LoadKey(key),
      LoadNonce(absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f")));
  // Write zeros to non-sensitive fields. This allows us to compare the whole
  // backing space of state with zeros after destruction.
  CleanseNonSensitiveStateFields(state);
  state->~Aegis128LState();
  for (int i = 0; i < sizeof(Aegis128LState); i++) {
    ASSERT_EQ(backing[i], 0);
  }
}
}  // namespace aegis

}  // namespace security

#endif  // __SSE2__
#endif  // __AES__