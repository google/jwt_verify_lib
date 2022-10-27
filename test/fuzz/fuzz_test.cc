// Copyright 2022 Google LLC
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

#include "jwt_verify_lib/jwt.h"
#include "jwt_verify_lib/jwks.h"
#include "jwt_verify_lib/verify.h"

#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"

#include <cstdint>
#include <cstddef>
#include <string>

namespace google {
namespace jwt_verify {
namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // split the data int "jwt . jwks".
  std::vector<std::string> v = absl::StrSplit(std::string((const char*)data, size), ".");
  // jwt has 2 dot, at least we should have 3 dots with 4 sections.
  if (v.size() < 4) return 0;

  // jwt section has 2 dots with 3 sections.
  std::vector<std::string> v_jwt = {v.begin(), v.begin() + 3};
  std::string jwt_str = absl::StrJoin(v_jwt, ".");

  // jwks section: the remaining after the 3rd dot.
  std::vector<std::string> v_jwks = {v.begin() + 3, v.end()};
  std::string jwks_str = absl::StrJoin(v_jwks, ".");

  Jwt jwt;
  auto jwt_status = jwt.parseFromString(jwt_str);

  auto jwks1 = Jwks::createFrom(jwks_str, Jwks::JWKS);
  auto jwks2 = Jwks::createFrom(jwks_str, Jwks::PEM);

  if (jwt_status == Status::Ok) {
    if (jwks1->getStatus() == Status::Ok) {
      verifyJwt(jwt, *jwks1);
    }
    if (jwks2->getStatus() == Status::Ok) {
      verifyJwt(jwt, *jwks2);
    }
  }
  return 0;
}

}  // namespace
}  // namespace jwt_verify
}  // namespace google
