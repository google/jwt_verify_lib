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

#include "google/protobuf/struct.pb.h"

namespace google {
namespace jwt_verify {

class StructUtils {
 public:
  StructUtils(const ::google::protobuf::Struct& struct_pb)
      : struct_pb_(struct_pb) {}

  enum FindResult {
    OK = 0,
    MISSING,
    WRONG_TYPE,
  };

  FindResult GetString(const std::string& name, std::string* value) {
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

  enum RequirementType {
    MUST_EXIST = 0,
    OPTIONAL,
  };

  bool GetString(const std::string& name, RequirementType require,
                 std::string* value) {
    auto ret = GetString(name, value);
    return (ret == OK || (ret == MISSING && require == OPTIONAL));
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

}  // namespace jwt_verify
}  // namespace google
