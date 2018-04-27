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

#include "base64.h"
#include "gtest/gtest.h"

namespace google {

TEST(Base64Test, EncodeString) {
  EXPECT_EQ("", Base64::encode("", 0));
  EXPECT_EQ("AAA=", Base64::encode("\0\0", 2));
  EXPECT_EQ("Zm9v", Base64::encode("foo", 3));
  EXPECT_EQ("Zm8=", Base64::encode("fo", 2));
}

TEST(Base64Test, Decode) {
  EXPECT_EQ("", Base64::decode(""));
  EXPECT_EQ("foo", Base64::decode("Zm9v"));
  EXPECT_EQ("fo", Base64::decode("Zm8="));
  EXPECT_EQ("f", Base64::decode("Zg=="));
  EXPECT_EQ("foobar", Base64::decode("Zm9vYmFy"));
  EXPECT_EQ("foob", Base64::decode("Zm9vYg=="));

  {
    const char* test_string = "\0\1\2\3\b\n\t";
    EXPECT_FALSE(memcmp(test_string, Base64::decode("AAECAwgKCQ==").data(), 7));
  }

  {
    const char* test_string = "\0\0\0\0als;jkopqitu[\0opbjlcxnb35g]b[\xaa\b\n";
    EXPECT_FALSE(memcmp(test_string,
                        Base64::decode(Base64::encode(test_string, 36)).data(),
                        36));
  }

  {
    const char* test_string =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded = Base64::decode(test_string);
    EXPECT_EQ(test_string, Base64::encode(decoded.c_str(), decoded.length()));
  }
}

TEST(Base64Test, DecodeFailure) {
  EXPECT_EQ("", Base64::decode("==Zg"));
  EXPECT_EQ("", Base64::decode("=Zm8"));
  EXPECT_EQ("", Base64::decode("Zm=8"));
  EXPECT_EQ("", Base64::decode("Zg=A"));
  EXPECT_EQ("", Base64::decode("Zh=="));  // 011001 100001 <- unused bit at tail
  EXPECT_EQ("", Base64::decode(
                    "Zm9="));  // 011001 100110 111101 <- unused bit at tail
  EXPECT_EQ("", Base64::decode("Zg.."));
  EXPECT_EQ("", Base64::decode("..Zg"));
  EXPECT_EQ("", Base64::decode("A==="));
  EXPECT_EQ("", Base64::decode("123"));
}

TEST(Base64UrlTest, Decode) {
  EXPECT_EQ("", Base64Url::decode(""));
  EXPECT_EQ("foo", Base64Url::decode("Zm9v"));
  EXPECT_EQ("fo", Base64Url::decode("Zm8"));
  EXPECT_EQ("f", Base64Url::decode("Zg"));
  EXPECT_EQ("foobar", Base64Url::decode("Zm9vYmFy"));
  EXPECT_EQ("foob", Base64Url::decode("Zm9vYg"));

  {
    const char* test_string = "\0\1\2\3\b\n\t";
    EXPECT_FALSE(
        memcmp(test_string, Base64Url::decode("AAECAwgKCQ").data(), 7));
  }

  {
    const char* test_string = "\0\0\0\0als;jkopqitu[\0opbjlcxnb35g]b[\xaa\b\n";
    EXPECT_FALSE(memcmp(
        test_string,
        Base64Url::decode(Base64Url::encode(test_string, 36)).data(), 36));
  }

  {
    const char* test_string =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string decoded = Base64Url::decode(test_string);
    EXPECT_EQ(test_string,
              Base64Url::encode(decoded.c_str(), decoded.length()));
  }

  {
    const char* url_test_string =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char* test_string =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    EXPECT_EQ(Base64Url::decode(url_test_string), Base64::decode(test_string));
  }
}

TEST(Base64UrlTest, DecodeFailure) {
  EXPECT_EQ("", Base64Url::decode("==Zg"));
  EXPECT_EQ("", Base64Url::decode("=Zm8"));
  EXPECT_EQ("", Base64Url::decode("Zm=8"));
  EXPECT_EQ("", Base64Url::decode("Zg=A"));
  EXPECT_EQ("",
            Base64Url::decode("Zh=="));  // 011001 100001 <- unused bit at tail
  EXPECT_EQ("", Base64Url::decode(
                    "Zm9="));  // 011001 100110 111101 <- unused bit at tail
  EXPECT_EQ("", Base64Url::decode("Zg.."));
  EXPECT_EQ("", Base64Url::decode("..Zg"));
  EXPECT_EQ("", Base64Url::decode("A==="));
  EXPECT_EQ("",
            Base64Url::decode("Zh"));  // 011001 100001 <- unused bit at tail
  EXPECT_EQ("", Base64Url::decode(
                    "Zm9"));  // 011001 100110 111101 <- unused bit at tail
  EXPECT_EQ("", Base64Url::decode("A"));
}
}  // namespace google
