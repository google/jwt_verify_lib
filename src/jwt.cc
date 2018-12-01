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

class StructGetter {
 public:
  StructGetter(const ::google::protobuf::Struct& struct_pb)
      : struct_pb_(struct_pb) {}

  enum RequirementType {
    MUST_EXIST = 0,
    OPTIONAL,
  };

  bool GetString(const std::string& name, RequirementType require,
                 std::string* value) {
    const auto& fields = struct_pb_.fields();
    const auto it = fields.find(name);
    if (it == fields.end()) {
      return require == OPTIONAL;
    }
    if (it->second.kind_case() != google::protobuf::Value::kStringValue) {
      return false;
    }
    *value = it->second.string_value();
    return true;
  }

  bool GetInt64(const std::string& name, RequirementType require,
                int64_t* value) {
    const auto& fields = struct_pb_.fields();
    const auto it = fields.find(name);
    if (it == fields.end()) {
      return require == OPTIONAL;
    }
    if (it->second.kind_case() != google::protobuf::Value::kNumberValue) {
      return false;
    }
    *value = it->second.number_value();
    return true;
  }

  // Get string or list of string, designed to get "aud" field
  // "aud" can be either string array or string.
  // Try as string array, read it as empty array if doesn't exist.
  bool GetStringList(const std::string& name, RequirementType require,
                     std::vector<std::string>* list) {
    const auto& fields = struct_pb_.fields();
    const auto it = fields.find(name);
    if (it == fields.end()) {
      return require == OPTIONAL;
    }
    if (it->second.kind_case() == google::protobuf::Value::kStringValue) {
      list->push_back(it->second.string_value());
      return true;
    }
    if (it->second.kind_case() == google::protobuf::Value::kListValue) {
      for (const auto& v : it->second.list_value().values()) {
        if (v.kind_case() != google::protobuf::Value::kStringValue) {
          return false;
        }
        list->push_back(v.string_value());
      }
      return true;
    }
    return false;
  }

 private:
  const ::google::protobuf::Struct& struct_pb_;
};

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
      Protobuf::util::JsonStringToMessage(header_str_, &header_pb_, options);
  if (!header_status.ok()) {
    return Status::JwtHeaderParseError;
  }

  StructGetter header_getter(header_pb_);
  // Header should contain "alg" and should be a string.
  if (!header_getter.GetString("alg", StructGetter::MUST_EXIST, &alg_)) {
    return Status::JwtHeaderBadAlg;
  }

  if (alg_ != "RS256" && alg_ != "ES256") {
    return Status::JwtHeaderNotImplementedAlg;
  }

  // Header may contain "kid", should be a string if exists.
  if (!header_getter.GetString("kid", StructGetter::OPTIONAL, &kid_)) {
    return Status::JwtHeaderBadKid;
  }

  // Parse payload json
  payload_str_base64url_ = std::string(jwt_split[1]);
  if (!absl::WebSafeBase64Unescape(payload_str_base64url_, &payload_str_)) {
    return Status::JwtPayloadParseError;
  }

  const auto payload_status =
      Protobuf::util::JsonStringToMessage(payload_str_, &payload_pb_, options);
  if (!payload_status.ok()) {
    return Status::JwtPayloadParseError;
  }

  StructGetter payload_getter(payload_pb_);
  if (!payload_getter.GetString("iss", StructGetter::OPTIONAL, &iss_)) {
    return Status::JwtPayloadParseError;
  }
  if (!payload_getter.GetString("sub", StructGetter::OPTIONAL, &sub_)) {
    return Status::JwtPayloadParseError;
  }

  if (!payload_getter.GetInt64("iat", StructGetter::OPTIONAL, &iat_)) {
    return Status::JwtPayloadParseError;
  }
  if (!payload_getter.GetInt64("nbf", StructGetter::OPTIONAL, &nbf_)) {
    return Status::JwtPayloadParseError;
  }
  if (!payload_getter.GetInt64("exp", StructGetter::OPTIONAL, &exp_)) {
    return Status::JwtPayloadParseError;
  }

  if (!payload_getter.GetString("jti", StructGetter::OPTIONAL, &jti_)) {
    return Status::JwtPayloadParseError;
  }

  // "aud" can be either string array or string.
  // Try as string array, read it as empty array if doesn't exist.
  if (!payload_getter.GetStringList("aud", StructGetter::OPTIONAL,
                                    &audiences_)) {
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
