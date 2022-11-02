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
                                               std::string* str_value) {
  const ::google::protobuf::Value* value;
  FindResult err = findNestedField(name, value);
  if (err == OK) {
    if (value->kind_case() != google::protobuf::Value::kStringValue) {
      return WRONG_TYPE;
    }
    *str_value = value->string_value();
  }
  return err;
}

StructUtils::FindResult StructUtils::GetUInt64(const std::string& name,
                                               uint64_t* int_value) {
  // const auto& fields = struct_pb_.fields();
  // const auto it = fields.find(name);
  // if (it == fields.end()) {
  //   return MISSING;
  // }
  // if (it->second.kind_case() != google::protobuf::Value::kNumberValue) {
  //   return WRONG_TYPE;
  // }
  // if (it->second.number_value() < 0) {
  //   return NOT_POSITIVE;
  // }
  // *int_value = static_cast<uint64_t>(it->second.number_value());
  // return OK;
  const ::google::protobuf::Value* value;
  FindResult err = findNestedField(name, value);
  if (err == OK) {
    if (value->kind_case() != google::protobuf::Value::kNumberValue) {
      return WRONG_TYPE;
    }
    if (value->number_value() < 0) {
      return NOT_POSITIVE;
    }
    *int_value = static_cast<uint64_t>(value->number_value());
  }
  return err;
}

StructUtils::FindResult StructUtils::GetBoolean(const std::string& name,
                                                bool* bool_value) {
  // const auto& fields = struct_pb_.fields();
  // const auto it = fields.find(name);
  // if (it == fields.end()) {
  //   return MISSING;
  // }
  // if (it->second.kind_case() != google::protobuf::Value::kBoolValue) {
  //   return WRONG_TYPE;
  // }
  // *bool_value = it->second.bool_value();
  // return OK;
  const ::google::protobuf::Value* value;
  FindResult err = findNestedField(name, value);
  if (err == OK) {
    if (value->kind_case() != google::protobuf::Value::kBoolValue) {
      return WRONG_TYPE;
    }
    *bool_value = value->bool_value();
  }
  return err;
}

StructUtils::FindResult StructUtils::GetStringList(
    const std::string& name, std::vector<std::string>* list) {
  const ::google::protobuf::Value* value;
  FindResult err = findNestedField(name, value);
  if (err == OK) {
    if (value->kind_case() == google::protobuf::Value::kStringValue) {
      list->push_back(value->string_value());
      return OK;
    }
    if (value->kind_case() == google::protobuf::Value::kListValue) {
      for (const auto& v : value->list_value().values()) {
        if (v.kind_case() != google::protobuf::Value::kStringValue) {
          return WRONG_TYPE;
        }
        list->push_back(v.string_value());
      }
      return OK;
    }
    return WRONG_TYPE;
  }
  return err;
}

StructUtils::FindResult StructUtils::findNestedField(
    const std::string& name, const google::protobuf::Value*& value) {
  const std::vector<absl::string_view> name_vector = absl::StrSplit(name, '.');

  const google::protobuf::Struct* current_struct = &struct_pb_;
  for (int i = 0; i < name_vector.size(); ++i) {
    const auto& fields = current_struct->fields();
    const auto it = fields.find(std::string(name_vector[i]));
    if (it == fields.end()) {
      return MISSING;
    }
    if (i == name_vector.size() - 1) {
      value = &it->second;
      return OK;
    }
    if (it->second.kind_case() != google::protobuf::Value::kStructValue) {
      return WRONG_TYPE;
    }
    current_struct = &it->second.struct_value();
  }
  return NOT_REACHABLE;
}

}  // namespace jwt_verify
}  // namespace google
