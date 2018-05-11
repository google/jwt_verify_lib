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
// limitations under the License.#pragma once

#pragma once

#include <string>
#include <vector>

#include "include/jwt_verify_lib/status.h"

namespace google {
namespace jwt_verify {

/**
 * struct to hold a JWT data.
 */
struct Jwt {
  // header string
  std::string header_str_;
  // header base64_url encoded
  std::string header_str_base64url_;

  // payload string
  std::string payload_str_;
  // payload base64_url encoded
  std::string payload_str_base64url_;
  // signature string
  std::string signature_;
  // alg
  std::string alg_;
  // kid
  std::string kid_;
  // iss
  std::string iss_;
  // audiences
  std::vector<std::string> audiences_;
  // sub
  std::string sub_;
  // expiration
  int64_t exp_ = 0;

  /**
   * Parse Jwt from string text
   * @return the status.
   */
  Status parseFromString(const std::string& jwt);
};

}  // namespace jwt_verify
}  // namespace google
