// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstdint>
#include <string>

namespace google {

/**
 * A utility class to support base64 encoding, which is defined in RFC4648
 * Section 4.
 * See https://tools.ietf.org/html/rfc4648#section-4
 */
class Base64 {
 public:
  /**
   * Base64 encode an input char buffer with a given length.
   * @param input char array to encode.
   * @param length of the input array.
   */
  static std::string encode(const char* input, uint64_t length);

  /**
   * Base64 decode an input string. Padding is required.
   * @param input supplies the input to decode.
   *
   * Note, decoded string may contain '\0' at any position, it should be treated
   * as a sequence of bytes.
   */
  static std::string decode(const std::string& input);
};

/**
 * A utility class to support base64url encoding, which is defined in RFC4648
 * Section 5.
 * See https://tools.ietf.org/html/rfc4648#section-5
 */
class Base64Url {
 public:
  /**
   * Base64url encode an input char buffer with a given length.
   * @param input char array to encode.
   * @param length of the input array.
   */
  static std::string encode(const char* input, uint64_t length);

  /**
   * Base64url decode an input string. Padding must not be included in the
   * input.
   * @param input supplies the input to decode.
   *
   * Note, decoded string may contain '\0' at any position, it should be treated
   * as a sequence of bytes.
   */
  static std::string decode(const std::string& input);
};

}  // namespace google
