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

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace google {
namespace json {
class Object;

typedef std::shared_ptr<Object> ObjectSharedPtr;

// @return false if immediate exit from iteration required.
typedef std::function<bool(const std::string&, const Object&)> ObjectCallback;

/**
 * Exception thrown when a JSON error occurs.
 */
class Exception : public std::runtime_error {
 public:
  Exception(const std::string& message) : std::runtime_error(message) {}
};

/**
 * Wraps an individual JSON node.
 */
class Object {
 public:
  virtual ~Object() {}

  /**
   * Convert a generic object into an array of objects. This is useful for
   * dealing
   * with arrays of arrays.
   * @return std::vector<ObjectSharedPtr> the converted object.
   */
  virtual std::vector<ObjectSharedPtr> asObjectArray() const = 0;

  /**
   * Get a boolean value by name.
   * @param name supplies the key name.
   * @return bool the value.
   */
  virtual bool getBoolean(const std::string& name) const = 0;

  /**
   * Get a boolean value by name.
   * @param name supplies the key name.
   * @param default_value supplies the value to return if the name does not
   * exist.
   * @return bool the value.
   */
  virtual bool getBoolean(const std::string& name,
                          bool default_value) const = 0;

  /**
   * Get an integer value by name.
   * @param name supplies the key name.
   * @return int64_t the value.
   */
  virtual int64_t getInteger(const std::string& name) const = 0;

  /**
   * Get an integer value by name or return a default if name does not exist.
   * @param name supplies the key name.
   * @param default_value supplies the value to return if name does not exist.
   * @return int64_t the value.
   */
  virtual int64_t getInteger(const std::string& name,
                             int64_t default_value) const = 0;

  /**
   * Get a sub-object by name.
   * @param name supplies the key name.
   * @param allow_empty supplies whether to return an empty object if the key
   * does not
   * exist.
   * @return ObjectObjectSharedPtr the sub-object.
   */
  virtual ObjectSharedPtr getObject(const std::string& name,
                                    bool allow_empty = false) const = 0;

  /**
   * Determine if an object is null.
   * @return bool is the object null?
   */
  virtual bool isNull() const = 0;

  /**
   * Get an array by name.
   * @param name supplies the key name.
   * @param allow_empty specifies whether to return an empty array if the key
   * does not exist.
   * @return std::vector<ObjectSharedPtr> the array of JSON  objects.
   */
  virtual std::vector<ObjectSharedPtr> getObjectArray(
      const std::string& name, bool allow_empty = false) const = 0;

  /**
   * Get a string value by name.
   * @param name supplies the key name.
   * @return std::string the value.
   */
  virtual std::string getString(const std::string& name) const = 0;

  /**
   * Get a string value by name or return a default if name does not exist.
   * @param name supplies the key name.
   * @param default_value supplies the value to return if name does not exist.
   * @return std::string the value.
   */
  virtual std::string getString(const std::string& name,
                                const std::string& default_value) const = 0;

  /**
   * Get a string array by name.
   * @param name supplies the key name.
   * @param allow_empty specifies whether to return an empty array if the key
   * does not exist.
   * @return std::vector<std::string> the array of strings.
   */
  virtual std::vector<std::string> getStringArray(
      const std::string& name, bool allow_empty = false) const = 0;

  /**
   * Get a double value by name.
   * @param name supplies the key name.
   * @return double the value.
   */
  virtual double getDouble(const std::string& name) const = 0;

  /**
   * Get a double value by name.
   * @param name supplies the key name.
   * @param default_value supplies the value to return if name does not exist.
   * @return double the value.
   */
  virtual double getDouble(const std::string& name,
                           double default_value) const = 0;

  /**
   * @return a hash of the JSON object. This is a hash of each nested element in
   * stable order.
   *         It does not consider white space that was originally in the parsed
   * JSON.
   */
  virtual uint64_t hash() const = 0;

  /**
   * Iterate over key-value pairs in an Object and call callback on each pair.
   */
  virtual void iterate(const ObjectCallback& callback) const = 0;

  /**
   * @return TRUE if the Object contains the key.
   * @param name supplies the key name to lookup.
   */
  virtual bool hasObject(const std::string& name) const = 0;

  /**
   * Validates JSON object against passed in schema.
   * @param schema supplies the schema in string format. A json::Exception will
   * be thrown if
   *        the JSON object doesn't conform to the supplied schema or the schema
   * itself is not
   *        valid.
   */
  virtual void validateSchema(const std::string& schema) const = 0;

  /**
   * @return the value of the object as a string (where the object is a string).
   */
  virtual std::string asString() const = 0;

  /**
   * @return the value of the object as a boolean (where the object is a
   * boolean).
   */
  virtual bool asBoolean() const = 0;

  /**
   * @return the value of the object as a double (where the object is a double).
   */
  virtual double asDouble() const = 0;

  /**
   * @return the value of the object as an integer (where the object is an
   * integer).
   */
  virtual int64_t asInteger() const = 0;

  /**
   * @return the JSON string representation of the object.
   */
  virtual std::string asJsonString() const = 0;

  /**
   * @return true if the JSON object is empty;
   */
  virtual bool empty() const = 0;
};

}  // namespace json
}  // namespace google
