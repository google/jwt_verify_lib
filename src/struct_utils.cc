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

#include "jwt_verify_lib/struct_utils.h"

namespace google {
namespace jwt_verify {

StructUtils::StructUtils(const ::google::protobuf::Struct& struct_pb)
    : struct_pb_(struct_pb) {}

StructUtils::FindResult StructUtils::GetString(const std::string& name,
                                               std::string* value) {
  const auto& fields = struct_pb_.fields();
  const auto it = fields.find(name);
  if (it == fields.end()) {
    return MISSING;
  }
  if (it->second.kind_case() != google::protobuf::Value::kStringValue) {
    return WRONG_TYPE;
  }
  *value = it->second.string_value();
  return OK;
}

StructUtils::FindResult StructUtils::GetInt64(const std::string& name,
                                              uint64_t* value) {
  const auto& fields = struct_pb_.fields();
  const auto it = fields.find(name);
  if (it == fields.end()) {
    return MISSING;
  }
  if (it->second.kind_case() != google::protobuf::Value::kNumberValue) {
    return WRONG_TYPE;
  }
  *value = static_cast<uint64_t>(it->second.number_value());
  return OK;
}

StructUtils::FindResult StructUtils::GetStringList(
    const std::string& name, std::vector<std::string>* list) {
  const auto& fields = struct_pb_.fields();
  const auto it = fields.find(name);
  if (it == fields.end()) {
    return MISSING;
  }
  if (it->second.kind_case() == google::protobuf::Value::kStringValue) {
    list->push_back(it->second.string_value());
    return OK;
  }
  if (it->second.kind_case() == google::protobuf::Value::kListValue) {
    for (const auto& v : it->second.list_value().values()) {
      if (v.kind_case() != google::protobuf::Value::kStringValue) {
        return WRONG_TYPE;
      }
      list->push_back(v.string_value());
    }
    return OK;
  }
  return WRONG_TYPE;
}

}  // namespace jwt_verify
}  // namespace google
