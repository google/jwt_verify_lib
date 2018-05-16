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

#include "jwt_verify_lib/jwt.h"
#include "gtest/gtest.h"

namespace google {
namespace jwt_verify {
namespace {

TEST(JwtParseTest, GoodJwt) {
  // JWT with
  // Header:  {"alg":"RS256","typ":"JWT"}
  // Payload:
  // {"iss":"https://example.com","sub":"test@example.com","exp":1501281058}
  const std::string jwt_text =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIs"
      "ImV4cCI6MTUwMTI4MTA1OH0.U2lnbmF0dXJl";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::Ok);

  EXPECT_EQ(jwt.alg_, "RS256");
  EXPECT_EQ(jwt.kid_, "");
  EXPECT_EQ(jwt.iss_, "https://example.com");
  EXPECT_EQ(jwt.sub_, "test@example.com");
  EXPECT_EQ(jwt.audiences_, std::vector<std::string>());
  EXPECT_EQ(jwt.exp_, 1501281058);
  EXPECT_EQ(jwt.signature_, "Signature");
}

TEST(JwtParseTest, GoodJwtWithMultiAud) {
  // aud: [aud1, aud2]
  const std::string jwt_text =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFmMDZjMTlmOGU1YjMzMTUyMT"
      "ZkZjAxMGZkMmI5YTkzYmFjMTM1YzgifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tI"
      "iwiaWF0IjoxNTE3ODc1MDU5LCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiZXhwIjoxNTE3ODc"
      "4NjU5LCJzdWIiOiJodHRwczovL2V4YW1wbGUuY29tIn0.U2lnbmF0dXJl";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::Ok);

  EXPECT_EQ(jwt.alg_, "RS256");
  EXPECT_EQ(jwt.kid_, "af06c19f8e5b3315216df010fd2b9a93bac135c8");
  EXPECT_EQ(jwt.iss_, "https://example.com");
  EXPECT_EQ(jwt.sub_, "https://example.com");
  EXPECT_EQ(jwt.audiences_, std::vector<std::string>({"aud1", "aud2"}));
  EXPECT_EQ(jwt.exp_, 1517878659);
  EXPECT_EQ(jwt.signature_, "Signature");
}

TEST(JwtParseTest, EmptyJwt) {
  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(""), Status::JwtBadFormat);
}

TEST(JwtParseTest, BadJsonHeader) {
  /*
   * jwt with header replaced by
   * "{"alg":"RS256","typ":"JWT", this is a invalid json}"
   */
  const std::string jwt_text =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIHRoaXMgaXMgYSBpbnZhbGlkIGpzb259."
      "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIs"
      "ImV4cCI6MTUwMTI4MTA1OH0.VGVzdFNpZ25hdHVyZQ";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::JwtHeaderParseError);
}

TEST(JwtParseTest, BadJsonPayload) {
  /*
   * jwt with payload replaced by
   * "this is not a json"
   */
  const std::string jwt_text =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.dGhpcyBpcyBub3QgYSBqc29u."
      "VGVzdFNpZ25hdHVyZQ";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::JwtPayloadParseError);
}

TEST(JwtParseTest, AbsentAlg) {
  /*
   * jwt with header replaced by
   * "{"typ":"JWT"}"
   */
  const std::string jwt_text =
      "eyJ0eXAiOiJKV1QifQ."
      "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIs"
      "ImV4cCI6MTUwMTI4MTA1OH0"
      ".VGVzdFNpZ25hdHVyZQ";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::JwtHeaderBadAlg);
}

TEST(JwtParseTest, AlgIsNotString) {
  /*
   * jwt with header replaced by
   * "{"alg":256,"typ":"JWT"}"
   */
  const std::string jwt_text =
      "eyJhbGciOjI1NiwidHlwIjoiSldUIn0."
      "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIs"
      "ImV4cCI6MTUwMTI4MTA1OH0.VGVzdFNpZ25hdHVyZQ";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::JwtHeaderBadAlg);
}

TEST(JwtParseTest, InvalidAlg) {
  /*
   * jwt with header replaced by
   * "{"alg":"InvalidAlg","typ":"JWT"}"
   */
  const std::string jwt_text =
      "eyJhbGciOiJJbnZhbGlkQWxnIiwidHlwIjoiSldUIn0."
      "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIs"
      "ImV4cCI6MTUwMTI4MTA1OH0.VGVzdFNpZ25hdHVyZQ";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::JwtHeaderNotImplementedAlg);
}

TEST(JwtParseTest, BadFormatKid) {
  // JWT with bad-formatted kid
  // Header:  {"alg":"RS256","typ":"JWT","kid":1}
  // Payload:
  // {"iss":"https://example.com","sub":"test@example.com","exp":1501281058}
  const std::string jwt_text =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0."
      "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIs"
      "ImV4cCI6MTUwMTI4MTA1OH0.VGVzdFNpZ25hdHVyZQ";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::JwtHeaderBadKid);
}

TEST(JwtParseTest, InvalidSignature) {
  // {"iss":"https://example.com","sub":"test@example.com","exp":1501281058,
  // aud: [aud1, aud2] }
  // signature part is invalid.
  const std::string jwt_text =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFmMDZjMTlmOGU1YjMzMTUyMT"
      "ZkZjAxMGZkMmI5YTkzYmFjMTM1YzgifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tI"
      "iwiaWF0IjoxNTE3ODc1MDU5LCJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiZXhwIjoxNTE3ODc"
      "4NjU5LCJzdWIiOiJodHRwczovL2V4YW1wbGUuY29tIn0.invalid-signature";

  Jwt jwt;
  ASSERT_EQ(jwt.parseFromString(jwt_text), Status::JwtSignatureParseError);
}

}  // namespace
}  // namespace jwt_verify
}  // namespace google
