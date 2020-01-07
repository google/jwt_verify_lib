// Copyright 2020 Google LLC
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

#include "gtest/gtest.h"
#include "jwt_verify_lib/verify.h"
#include "src/test_common.h"

namespace google {
namespace jwt_verify {
namespace {

// Token generated with the following header and payload and kOkPrivateKey.
// Header (kid is not specified):
// {
//   "alg": "RS256",
//   "typ": "JWT"
// }
// Payload:
// {
//   "iss": "628645741881-"
//     "noabiu23f5a8m8ovd8ucv698lj78vv0l@developer.gserviceaccount.com",
//   "sub": "628645741881-"
//     "noabiu23f5a8m8ovd8ucv698lj78vv0l@developer.gserviceaccount.com",
//   "aud": "http://myservice.com/myapi"
// }
const std::string kTokenNoKid =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiI2Mjg2NDU3NDE4ODEtbm9hYml1M"
    "jNmNWE4bThvdmQ4dWN2Njk4bGo3OHZ2MGxAZGV2ZWxvcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20"
    "iLCJzdWIiOiI2Mjg2NDU3NDE4ODEtbm9hYml1MjNmNWE4bThvdmQ4dWN2Njk4bGo3OHZ2MGxAZ"
    "GV2ZWxvcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJodHRwOi8vbXlzZXJ2aWNlLmN"
    "vbS9teWFwaSJ9.gq_4ucjddQDjYK5FJr_kXmMo2fgSEB6Js1zopcQLVpCKFDNb-TQ97go0wuk5"
    "_vlSp_8I2ImrcdwYbAKqYCzcdyBXkAYoHCGgmY-v6MwZFUvrIaDzR_M3rmY8sQ8cdN3MN6ZRbB"
    "6opHwDP1lUEx4bZn_ZBjJMPgqbIqGmhoT1UpfPF6P1eI7sXYru-4KVna0STOynLl3d7JYb7E-8"
    "ifcjUJLhat8JR4zR8i4-zWjn6d6j_NI7ZvMROnao77D9YyhXv56zfsXRatKzzYtxPlQMz4AjP-"
    "bUHfbHmhiIOOAeEKFuIVUAwM17j54M6VQ5jnAabY5O-ermLfwPiXvNt2L2SA==";

TEST(VerifyX509Test, NoKidToken) {
  Jwt jwt;
  EXPECT_EQ(jwt.parseFromString(kTokenNoKid), Status::Ok);

  auto jwks = Jwks::createFrom(kPublicKeyX509, Jwks::Type::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);

  EXPECT_EQ(verifyJwt(jwt, *jwks), Status::Ok);

  fuzzJwtSignature(jwt, [&jwks](const Jwt& jwt) {
    EXPECT_EQ(verifyJwt(jwt, *jwks), Status::JwtVerificationFail);
  });
}

}  // namespace
}  // namespace jwt_verify
}  // namespace google
