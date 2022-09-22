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
  StructUtils(const ::google::protobuf::Struct& struct_pb);

  enum FindResult {
    OK = 0,
    MISSING,
    WRONG_TYPE,
    NOT_POSITIVE,
  };

  FindResult GetString(const std::string& name, std::string* value);

  FindResult GetUInt64(const std::string& name, uint64_t* value);

  // Get string or list of string, designed to get "aud" field
  // "aud" can be either string array or string.
  // Try as string array, read it as empty array if doesn't exist.
  FindResult GetStringList(const std::string& name,
                           std::vector<std::string>* list);

 private:
  const ::google::protobuf::Struct& struct_pb_;
};

}  // namespace jwt_verify
}  // namespace google
