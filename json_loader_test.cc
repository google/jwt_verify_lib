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

#include <string>
#include <vector>

#include "json_loader.h"

#include "gtest/gtest.h"

namespace google {
namespace json {

#define EXPECT_THROW_WITH_MESSAGE(statement, expected_exception, message) \
  try {                                                                   \
    statement;                                                            \
    ADD_FAILURE() << "Exception should take place. It did not.";          \
  } catch (expected_exception & e) {                                      \
    EXPECT_EQ(message, std::string(e.what()));                            \
  }

TEST(JsonLoaderTest, Basic) {
  EXPECT_THROW(Factory::loadFromString("{"), Exception);

  {
    ObjectSharedPtr json = Factory::loadFromString("{\"hello\":123}");
    EXPECT_TRUE(json->hasObject("hello"));
    EXPECT_FALSE(json->hasObject("world"));
    EXPECT_FALSE(json->empty());
    EXPECT_THROW(json->getObject("world"), Exception);
    EXPECT_THROW(json->getObject("hello"), Exception);
    EXPECT_THROW(json->getBoolean("hello"), Exception);
    EXPECT_THROW(json->getObjectArray("hello"), Exception);
    EXPECT_THROW(json->getString("hello"), Exception);

    EXPECT_THROW_WITH_MESSAGE(
        json->getString("hello"), Exception,
        "key 'hello' missing or not a string from lines 1-1");
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{\"hello\":\"123\"\n}");
    EXPECT_THROW_WITH_MESSAGE(
        json->getInteger("hello"), Exception,
        "key 'hello' missing or not an integer from lines 1-2");
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{\"hello\":true}");
    EXPECT_TRUE(json->getBoolean("hello"));
    EXPECT_TRUE(json->getBoolean("hello", false));
    EXPECT_FALSE(json->getBoolean("world", false));
  }

  {
    ObjectSharedPtr json =
        Factory::loadFromString("{\"hello\": [\"a\", \"b\", 3]}");
    EXPECT_THROW(json->getStringArray("hello"), Exception);
    EXPECT_THROW(json->getStringArray("world"), Exception);
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{\"hello\":123}");
    EXPECT_EQ(123, json->getInteger("hello", 456));
    EXPECT_EQ(456, json->getInteger("world", 456));
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{\"hello\": \n[123]}");

    EXPECT_THROW_WITH_MESSAGE(
        json->getObjectArray("hello").at(0)->getString("hello"), Exception,
        "JSON field from line 2 accessed with type 'Object' does not match "
        "actual type 'Integer'.");
  }

  {
    EXPECT_THROW_WITH_MESSAGE(
        Factory::loadFromString("{\"hello\": \n\n\"world\""), Exception,
        "JSON supplied is not valid. Error(offset 19, line 3): Missing a comma "
        "or "
        "'}' after an object member.\n");
  }

  {
    ObjectSharedPtr json_object = Factory::loadFromString("[\"foo\",\"bar\"]");
    EXPECT_FALSE(json_object->empty());
  }

  {
    ObjectSharedPtr json_object = Factory::loadFromString("[]");
    EXPECT_TRUE(json_object->empty());
  }

  {
    ObjectSharedPtr json = Factory::loadFromString(
        "{\"1\":{\"11\":\"111\"},\"2\":{\"22\":\"222\"}}");
    int pos = 0;
    json->iterate([&pos](const std::string& key, const json::Object& value) {
      EXPECT_TRUE(key == "1" || key == "2");

      if (key == "1") {
        EXPECT_EQ("111", value.getString("11"));
      } else {
        EXPECT_EQ("222", value.getString("22"));
      }

      pos++;
      return true;
    });

    EXPECT_EQ(2, pos);
  }

  {
    ObjectSharedPtr json = Factory::loadFromString(
        "{\"1\":{\"11\":\"111\"},\"2\":{\"22\":\"222\"}}");
    int pos = 0;
    json->iterate([&pos](const std::string& key, const json::Object& value) {
      EXPECT_TRUE(key == "1" || key == "2");

      if (key == "1") {
        EXPECT_EQ("111", value.getString("11"));
      } else {
        EXPECT_EQ("222", value.getString("22"));
      }

      pos++;
      return false;
    });

    EXPECT_EQ(1, pos);
  }

  {
    std::string json = R"EOF(
    {
      "descriptors": [
         [{"key": "hello", "value": "world"}, {"key": "foo", "value": "bar"}],
         [{"key": "foo2", "value": "bar2"}]
       ]
    }
    )EOF";

    ObjectSharedPtr config = Factory::loadFromString(json);
    EXPECT_EQ(2U,
              config->getObjectArray("descriptors")[0]->asObjectArray().size());
    EXPECT_EQ(1U,
              config->getObjectArray("descriptors")[1]->asObjectArray().size());
  }

  {
    std::string json = R"EOF(
    {
      "descriptors": ["hello", "world"]
    }
    )EOF";

    ObjectSharedPtr config = Factory::loadFromString(json);
    std::vector<ObjectSharedPtr> array = config->getObjectArray("descriptors");
    EXPECT_THROW(array[0]->asObjectArray(), Exception);
  }

  {
    std::string json = R"EOF({})EOF";
    ObjectSharedPtr config = Factory::loadFromString(json);
    ObjectSharedPtr object = config->getObject("foo", true);
    EXPECT_EQ(2, object->getInteger("bar", 2));
    EXPECT_TRUE(object->empty());
  }

  {
    std::string json = R"EOF({"foo": []})EOF";
    ObjectSharedPtr config = Factory::loadFromString(json);
    EXPECT_TRUE(config->getStringArray("foo").empty());
  }

  {
    std::string json = R"EOF({"foo": ["bar", "baz"]})EOF";
    ObjectSharedPtr config = Factory::loadFromString(json);
    EXPECT_FALSE(config->getStringArray("foo").empty());
  }

  {
    std::string json = R"EOF({})EOF";
    ObjectSharedPtr config = Factory::loadFromString(json);
    EXPECT_THROW(config->getStringArray("foo"), Exception);
  }

  {
    std::string json = R"EOF({})EOF";
    ObjectSharedPtr config = Factory::loadFromString(json);
    EXPECT_TRUE(config->getStringArray("foo", true).empty());
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{\"hello\": \n[2.0]}");
    EXPECT_THROW(json->getObjectArray("hello").at(0)->getDouble("foo"),
                 Exception);
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{\"hello\": \n[null]}");
    EXPECT_THROW(json->getObjectArray("hello").at(0)->getDouble("foo"),
                 Exception);
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{}");
    EXPECT_THROW(json->getObjectArray("hello").empty(), Exception);
  }

  {
    ObjectSharedPtr json = Factory::loadFromString("{}");
    EXPECT_TRUE(json->getObjectArray("hello", true).empty());
  }
}

TEST(JsonLoaderTest, Integer) {
  {
    ObjectSharedPtr json = Factory::loadFromString(
        "{\"max\":9223372036854775807, \"min\":-9223372036854775808}");
    EXPECT_EQ(std::numeric_limits<int64_t>::max(), json->getInteger("max"));
    EXPECT_EQ(std::numeric_limits<int64_t>::min(), json->getInteger("min"));
  }
  {
    EXPECT_THROW(Factory::loadFromString("{\"val\":9223372036854775808}"),
                 Exception);

    // I believe this is a bug with rapidjson.
    // It silently eats numbers below min int64_t with no exception.
    // Fail when reading key instead of on parse.
    ObjectSharedPtr json =
        Factory::loadFromString("{\"val\":-9223372036854775809}");
    EXPECT_THROW(json->getInteger("val"), Exception);
  }
}

TEST(JsonLoaderTest, Double) {
  {
    ObjectSharedPtr json =
        Factory::loadFromString("{\"value1\": 10.5, \"value2\": -12.3}");
    EXPECT_EQ(10.5, json->getDouble("value1"));
    EXPECT_EQ(-12.3, json->getDouble("value2"));
  }
  {
    ObjectSharedPtr json = Factory::loadFromString("{\"foo\": 13.22}");
    EXPECT_EQ(13.22, json->getDouble("foo", 0));
    EXPECT_EQ(0, json->getDouble("bar", 0));
  }
  {
    ObjectSharedPtr json = Factory::loadFromString("{\"foo\": \"bar\"}");
    EXPECT_THROW(json->getDouble("foo"), Exception);
  }
}

TEST(JsonLoaderTest, Hash) {
  ObjectSharedPtr json1 =
      Factory::loadFromString("{\"value1\": 10.5, \"value2\": -12.3}");
  ObjectSharedPtr json2 =
      Factory::loadFromString("{\"value2\": -12.3, \"value1\": 10.5}");
  ObjectSharedPtr json3 =
      Factory::loadFromString("  {  \"value2\":  -12.3, \"value1\":  10.5} ");
  EXPECT_NE(json1->hash(), json2->hash());
  EXPECT_EQ(json2->hash(), json3->hash());
}

TEST(JsonLoaderTest, Schema) {
  {
    std::string invalid_json_schema = R"EOF(
    {
      "properties": {"value1"}
    }
    )EOF";

    std::string invalid_schema = R"EOF(
    {
      "properties" : {
        "value1": {"type" : "faketype"}
      }
    }
    )EOF";

    std::string different_schema = R"EOF(
    {
      "properties" : {
        "value1" : {"type" : "number"}
      },
      "additionalProperties" : false
    }
    )EOF";

    std::string valid_schema = R"EOF(
    {
      "properties": {
        "value1": {"type" : "number"},
        "value2": {"type": "string"}
      },
      "additionalProperties": false
    }
    )EOF";

    std::string json_string = R"EOF(
    {
      "value1": 10,
      "value2" : "test"
    }
    )EOF";

    ObjectSharedPtr json = Factory::loadFromString(json_string);
    EXPECT_THROW(json->validateSchema(invalid_json_schema),
                 std::invalid_argument);
    EXPECT_THROW(json->validateSchema(invalid_schema), Exception);
    EXPECT_THROW(json->validateSchema(different_schema), Exception);
    EXPECT_NO_THROW(json->validateSchema(valid_schema));
  }

  {
    std::string json_string = R"EOF(
    {
      "value1": [false, 2.01, 3, null],
      "value2" : "test"
    }
    )EOF";

    std::string empty_schema = R"EOF({})EOF";

    ObjectSharedPtr json = Factory::loadFromString(json_string);
    EXPECT_NO_THROW(json->validateSchema(empty_schema));
  }
}

TEST(JsonLoaderTest, NestedSchema) {
  std::string schema = R"EOF(
  {
    "properties": {
      "value1": {"type" : "number"},
      "value2": {"type": "string"}
    },
    "additionalProperties": false
  }
  )EOF";

  std::string json_string = R"EOF(
  {
    "bar": "baz",
    "foo": {
      "value1": "should have been a number",
      "value2" : "test"
    }
  }
  )EOF";

  ObjectSharedPtr json = Factory::loadFromString(json_string);

  EXPECT_THROW_WITH_MESSAGE(
      json->getObject("foo")->validateSchema(schema), Exception,
      "JSON at lines 4-7 does not conform to schema.\n Invalid schema: "
      "#/properties/value1\n Schema violation: type\n Offending document "
      "key: #/value1");
}

TEST(JsonLoaderTest, MissingEnclosingDocument) {
  std::string json_string = R"EOF(
  "listeners" : [
    {
      "address": "tcp://127.0.0.1:1234",
      "filters": []
    }
  ]
  )EOF";

  EXPECT_THROW_WITH_MESSAGE(
      Factory::loadFromString(json_string), Exception,
      "JSON supplied is not valid. Error(offset 14, line 2): Terminate "
      "parsing due to Handler error.\n");
}

TEST(JsonLoaderTest, AsString) {
  ObjectSharedPtr json =
      Factory::loadFromString("{\"name1\": \"value1\", \"name2\": true}");
  json->iterate([&](const std::string& key, const json::Object& value) {
    EXPECT_TRUE(key == "name1" || key == "name2");

    if (key == "name1") {
      EXPECT_EQ("value1", value.asString());
    } else {
      EXPECT_THROW(value.asString(), Exception);
    }
    return true;
  });
}

TEST(JsonLoaderTest, AsJsonString) {
  // We can't do simply equality of asJsonString(), since there is a reliance on
  // internal ordering,
  // e.g. of map traversal, in the output.
  const std::string json_string = "{\"name1\": \"value1\", \"name2\": true}";
  const ObjectSharedPtr json = Factory::loadFromString(json_string);
  const ObjectSharedPtr json2 = Factory::loadFromString(json->asJsonString());
  EXPECT_EQ("value1", json2->getString("name1"));
  EXPECT_TRUE(json2->getBoolean("name2"));
}

}  // namespace json
}  // namespace google
