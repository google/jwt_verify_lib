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

#include <algorithm>

#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "google/protobuf/util/json_util.h"
#include "jwt_verify_lib/jwt.h"
#include "jwt_verify_lib/struct_utils.h"

namespace google {
namespace jwt_verify {

Jwt::Jwt(const Jwt& instance) { *this = instance; }

Jwt& Jwt::operator=(const Jwt& rhs) {
  parseFromString(rhs.jwt_);
  return *this;
}

Status Jwt::parseFromString(const std::string& jwt) {
  // jwt must have exactly 2 dots
  if (std::count(jwt.begin(), jwt.end(), '.') != 2) {
    return Status::JwtBadFormat;
  }
  jwt_ = jwt;
  std::vector<absl::string_view> jwt_split =
      absl::StrSplit(jwt, '.', absl::SkipEmpty());
  if (jwt_split.size() != 3) {
    return Status::JwtBadFormat;
  }

  // Parse header json
  header_str_base64url_ = std::string(jwt_split[0]);
  if (!absl::WebSafeBase64Unescape(header_str_base64url_, &header_str_)) {
    return Status::JwtHeaderParseError;
  }

  ::google::protobuf::util::JsonParseOptions options;
  const auto header_status = ::google::protobuf::util::JsonStringToMessage(
      header_str_, &header_pb_, options);
  if (!header_status.ok()) {
    return Status::JwtHeaderParseError;
  }

  StructUtils header_getter(header_pb_);
  // Header should contain "alg" and should be a string.
  if (header_getter.GetString("alg", &alg_) != StructUtils::OK) {
    return Status::JwtHeaderBadAlg;
  }

  if (alg_ != "RS256" && alg_ != "ES256" && alg_ != "RS384" &&
      alg_ != "RS512") {
    return Status::JwtHeaderNotImplementedAlg;
  }

  // Header may contain "kid", should be a string if exists.
  if (header_getter.GetString("kid", &kid_) == StructUtils::WRONG_TYPE) {
    return Status::JwtHeaderBadKid;
  }

  // Parse payload json
  payload_str_base64url_ = std::string(jwt_split[1]);
  if (!absl::WebSafeBase64Unescape(payload_str_base64url_, &payload_str_)) {
    return Status::JwtPayloadParseError;
  }

  const auto payload_status = ::google::protobuf::util::JsonStringToMessage(
      payload_str_, &payload_pb_, options);
  if (!payload_status.ok()) {
    return Status::JwtPayloadParseError;
  }

  StructUtils payload_getter(payload_pb_);
  if (payload_getter.GetString("iss", &iss_) == StructUtils::WRONG_TYPE) {
    return Status::JwtPayloadParseError;
  }
  if (payload_getter.GetString("sub", &sub_) == StructUtils::WRONG_TYPE) {
    return Status::JwtPayloadParseError;
  }

  if (payload_getter.GetInt64("iat", &iat_) == StructUtils::WRONG_TYPE) {
    return Status::JwtPayloadParseError;
  }
  if (payload_getter.GetInt64("nbf", &nbf_) == StructUtils::WRONG_TYPE) {
    return Status::JwtPayloadParseError;
  }
  if (payload_getter.GetInt64("exp", &exp_) == StructUtils::WRONG_TYPE) {
    return Status::JwtPayloadParseError;
  }

  if (payload_getter.GetString("jti", &jti_) == StructUtils::WRONG_TYPE) {
    return Status::JwtPayloadParseError;
  }

  // "aud" can be either string array or string.
  // Try as string array, read it as empty array if doesn't exist.
  if (payload_getter.GetStringList("aud", &audiences_) ==
      StructUtils::WRONG_TYPE) {
    return Status::JwtPayloadParseError;
  }

  // Set up signature
  if (!absl::WebSafeBase64Unescape(jwt_split[2], &signature_)) {
    // Signature is a bad Base64url input.
    return Status::JwtSignatureParseError;
  }
  return Status::Ok;
}

}  // namespace jwt_verify
}  // namespace google
