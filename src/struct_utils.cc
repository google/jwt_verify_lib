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

#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"

namespace google {
namespace jwt_verify {

StructUtils::StructUtils(const ::google::protobuf::Struct& struct_pb)
    : struct_pb_(struct_pb) {}

StructUtils::FindResult StructUtils::GetString(const std::string& name,
                                               std::string* str_value) {
  const ::google::protobuf::Value* found;
  FindResult result = GetValue(name, found);
  if (result != OK) {
    return result;
  }
  if (found->kind_case() != google::protobuf::Value::kStringValue) {
    return WRONG_TYPE;
  }
  *str_value = found->string_value();
  return OK;
}

StructUtils::FindResult StructUtils::GetDouble(const std::string& name,
                                               double* double_value) {
  const ::google::protobuf::Value* found;
  FindResult result = GetValue(name, found);
  if (result != OK) {
    return result;
  }
  if (found->kind_case() != google::protobuf::Value::kNumberValue) {
    return WRONG_TYPE;
  }
  *double_value = found->number_value();
  return OK;
}

StructUtils::FindResult StructUtils::GetUInt64(const std::string& name,
                                               uint64_t* int_value) {
  double double_value;
  FindResult result = GetDouble(name, &double_value);
  if (result != OK) {
    return result;
  }
  if (double_value < 0 ||
      double_value >=
          static_cast<double>(std::numeric_limits<uint64_t>::max())) {
    return OUT_OF_RANGE;
  }
  *int_value = static_cast<uint64_t>(double_value);
  return OK;
}

StructUtils::FindResult StructUtils::GetBoolean(const std::string& name,
                                                bool* bool_value) {
  const ::google::protobuf::Value* found;
  FindResult result = GetValue(name, found);
  if (result != OK) {
    return result;
  }
  if (found->kind_case() != google::protobuf::Value::kBoolValue) {
    return WRONG_TYPE;
  }
  *bool_value = found->bool_value();
  return OK;
}

StructUtils::FindResult StructUtils::GetStringList(
    const std::string& name, std::vector<std::string>* list) {
  const ::google::protobuf::Value* found;
  FindResult result = GetValue(name, found);
  if (result != OK) {
    return result;
  }
  if (found->kind_case() == google::protobuf::Value::kStringValue) {
    list->push_back(found->string_value());
    return OK;
  }
  if (found->kind_case() == google::protobuf::Value::kListValue) {
    for (const auto& v : found->list_value().values()) {
      if (v.kind_case() != google::protobuf::Value::kStringValue) {
        return WRONG_TYPE;
      }
      list->push_back(v.string_value());
    }
    return OK;
  }
  return WRONG_TYPE;
}

StructUtils::FindResult StructUtils::GetValue(
    const std::string& nested_names, const google::protobuf::Value*& found) {
  std::vector<std::string> name_vector;

  // Handle namespaced custom claims that by convention start with a URL - as
  // most URLs contain dots, we extract the URL up to the FQDN and then split
  // only the URL path by dots.
  //
  // e.g. for nested_names "https://example.com/claims.nested.key", name_vector
  // would be {"https://example.com/claims", "nested", "key"}
  if (absl::StartsWith(nested_names, "http://") ||
      absl::StartsWith(nested_names, "https://")) {
    const std::vector<std::string> url_components =
        absl::StrSplit(nested_names, absl::MaxSplits('/', 3));
    const std::string left = absl::StrJoin(
        {url_components[0], url_components[1], url_components[2]}, "/");
    const std::vector<std::string> path_components =
        absl::StrSplit(url_components[3], '.');
    name_vector = {absl::StrCat(left, "/", path_components[0])};
    name_vector.insert(std::end(name_vector),
                       std::next(std::begin(path_components)),
                       std::end(path_components));
  } else {
    name_vector = absl::StrSplit(nested_names, '.');
  }

  const google::protobuf::Struct* current_struct = &struct_pb_;
  for (int i = 0; i < name_vector.size(); ++i) {
    const auto& fields = current_struct->fields();
    const auto it = fields.find(std::string(name_vector[i]));
    if (it == fields.end()) {
      return MISSING;
    }
    if (i == name_vector.size() - 1) {
      found = &it->second;
      return OK;
    }
    if (it->second.kind_case() != google::protobuf::Value::kStructValue) {
      return WRONG_TYPE;
    }
    current_struct = &it->second.struct_value();
  }
  return MISSING;
}

}  // namespace jwt_verify
}  // namespace google
