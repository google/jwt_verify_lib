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
#include "jwt.h"
#include "rapidjson/document.h"

namespace google {
namespace jwt_verify {

Status Jwt::parseFromString(const std::string& jwt) {
  // jwt must have exactly 2 dots
  if (std::count(jwt.begin(), jwt.end(), '.') != 2) {
    return Status::JwtBadFormat;
  }
  std::vector<absl::string_view> jwt_split =
      absl::StrSplit(jwt, absl::ByAnyChar("."), absl::SkipEmpty());
  if (jwt_split.size() != 3) {
    return Status::JwtBadFormat;
  }

  // Parse header json
  header_str_base64url_ = std::string(jwt_split[0]);
  if (!absl::WebSafeBase64Unescape(header_str_base64url_, &header_str_)) {
    return Status::JwtHeaderParseError;
  }
  rapidjson::Document header_json;
  if (header_json.Parse(header_str_.c_str()).HasParseError()) {
    return Status::JwtHeaderParseError;
  }

  // Header should contain "alg" and should be a string.
  if (!header_json.HasMember("alg") || !header_json["alg"].IsString()) {
    return Status::JwtHeaderBadAlg;
  }
  alg_ = header_json["alg"].GetString();

  if (alg_ != "RS256" && alg_ != "ES256") {
    return Status::JwtHeaderNotImplementedAlg;
  }

  // Header may contain "kid", should be a string if exists.
  if (header_json.HasMember("kid")) {
    if (!header_json["kid"].IsString()) {
      return Status::JwtHeaderBadKid;
    }
    kid_ = header_json["kid"].GetString();
  }

  // Parse payload json
  payload_str_base64url_ = std::string(jwt_split[1]);
  if (!absl::WebSafeBase64Unescape(payload_str_base64url_, &payload_str_)) {
    return Status::JwtPayloadParseError;
  }

  rapidjson::Document payload_json;
  if (payload_json.Parse(payload_str_.c_str()).HasParseError()) {
    return Status::JwtPayloadParseError;
  }

  if (payload_json.HasMember("iss")) {
    if (payload_json["iss"].IsString()) {
      iss_ = payload_json["iss"].GetString();
    } else {
      return Status::JwtPayloadParseError;
    }
  }
  if (payload_json.HasMember("sub")) {
    if (payload_json["sub"].IsString()) {
      sub_ = payload_json["sub"].GetString();
    } else {
      return Status::JwtPayloadParseError;
    }
  }
  if (payload_json.HasMember("exp")) {
    if (payload_json["exp"].IsInt()) {
      exp_ = payload_json["exp"].GetInt();
    } else {
      return Status::JwtPayloadParseError;
    }
  } else {
    exp_ = 0;
  }

  // "aud" can be either string array or string.
  // Try as string array, read it as empty array if doesn't exist.
  if (payload_json.HasMember("aud")) {
    const auto& aud_value = payload_json["aud"];
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
