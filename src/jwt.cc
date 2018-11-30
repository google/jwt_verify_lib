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

  Protobuf::util::JsonParseOptions options;
  const auto header_status =
        Protobuf::util::JsonStringToMessage(header_str_, &header_struct_pb_, options);
  if (!header_status.ok()) {
    return Status::JwtHeaderParseError;
  }

  // Header should contain "alg" and should be a string.
  if (!header_struct_pb_.HasMember("alg") || !header_struct_pb_["alg"].IsString()) {
    return Status::JwtHeaderBadAlg;
  }
  alg_ = header_struct_pb_["alg"].GetString();

  if (alg_ != "RS256" && alg_ != "ES256") {
    return Status::JwtHeaderNotImplementedAlg;
  }

  // Header may contain "kid", should be a string if exists.
  if (header_struct_pb_.HasMember("kid")) {
    if (!header_struct_pb_["kid"].IsString()) {
      return Status::JwtHeaderBadKid;
    }
    kid_ = header_struct_pb_["kid"].GetString();
  }

  // Parse payload json
  payload_str_base64url_ = std::string(jwt_split[1]);
  if (!absl::WebSafeBase64Unescape(payload_str_base64url_, &payload_str_)) {
    return Status::JwtPayloadParseError;
  }

  const auto payload_status =
        Protobuf::util::JsonStringToMessage(payload_str_, &payload_struct_pb_, options);
  if (!payload_status.ok()) {
    return Status::JwtPayloadParseError;
  }

  if (payload_struct_pb_.HasMember("iss")) {
    if (payload_struct_pb_["iss"].IsString()) {
      iss_ = payload_struct_pb_["iss"].GetString();
    } else {
      return Status::JwtPayloadParseError;
    }
  }
  if (payload_struct_pb_.HasMember("sub")) {
    if (payload_struct_pb_["sub"].IsString()) {
      sub_ = payload_struct_pb_["sub"].GetString();
    } else {
      return Status::JwtPayloadParseError;
    }
  }
  if (payload_struct_pb_.HasMember("iat")) {
    if (payload_struct_pb_["iat"].IsInt64()) {
      iat_ = payload_struct_pb_["iat"].GetInt64();
    } else {
      return Status::JwtPayloadParseError;
    }
  } else {
    iat_ = 0;
  }
  if (payload_struct_pb_.HasMember("nbf")) {
    if (payload_struct_pb_["nbf"].IsInt64()) {
      nbf_ = payload_struct_pb_["nbf"].GetInt64();
    } else {
      return Status::JwtPayloadParseError;
    }
  } else {
    nbf_ = 0;
  }
  if (payload_struct_pb_.HasMember("exp")) {
    if (payload_struct_pb_["exp"].IsInt64()) {
      exp_ = payload_struct_pb_["exp"].GetInt64();
    } else {
      return Status::JwtPayloadParseError;
    }
  } else {
    exp_ = 0;
  }
  if (payload_struct_pb_.HasMember("jti")) {
    if (payload_struct_pb_["jti"].IsString()) {
      jti_ = payload_struct_pb_["jti"].GetString();
    } else {
      return Status::JwtPayloadParseError;
    }
  }

  // "aud" can be either string array or string.
  // Try as string array, read it as empty array if doesn't exist.
  if (payload_struct_pb_.HasMember("aud")) {
    const auto& aud_value = payload_struct_pb_["aud"];
    if (aud_value.IsArray()) {
      for (auto it = aud_value.Begin(); it != aud_value.End(); ++it) {
        if (it->IsString()) {
          audiences_.push_back(it->GetString());
        } else {
          return Status::JwtPayloadParseError;
        }
      }
    } else if (aud_value.IsString()) {
      audiences_.push_back(aud_value.GetString());
    } else {
      return Status::JwtPayloadParseError;
    }
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
