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

#include "jwt_verify_lib/jwks.h"
#include "gtest/gtest.h"

namespace google {
namespace jwt_verify {
namespace {

TEST(JwksParseTest, GoodPem) {
  // Public key PEM
  const std::string jwks_text =
      "MIIBCgKCAQEAtw7MNxUTxmzWROCD5BqJxmzT7xqc9KsnAjbXCoqEEHDx4WBlfcwk"
      "XHt9e/2+Uwi3Arz3FOMNKwGGlbr7clBY3utsjUs8BTF0kO/poAmSTdSuGeh2mSbc"
      "VHvmQ7X/kichWwx5Qj0Xj4REU3Gixu1gQIr3GATPAIULo5lj/ebOGAa+l0wIG80N"
      "zz1pBtTIUx68xs5ZGe7cIJ7E8n4pMX10eeuh36h+aossePeuHulYmjr4N0/1jG7a"
      "+hHYL6nqwOR3ej0VqCTLS0OloC0LuCpLV7CnSpwbp2Qg/c+MDzQ0TH8g8drIzR5h"
      "Fe9a3NlNRMXgUU5RqbLnR9zfXr7b9oEszQIDAQAB";

  auto jwks = Jwks::createFrom(jwks_text, Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
  EXPECT_EQ(jwks->keys().size(), 1);
  EXPECT_TRUE(jwks->keys()[0]->pem_format_);
}

TEST(JwksParseTest, EmptyPem) {
  auto jwks = Jwks::createFrom("", Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), Status::JwksPemBadBase64);
}

TEST(JwksParseTest, BadBase64Pem) {
  auto jwks = Jwks::createFrom("abc", Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), Status::JwksPemParseError);
}

TEST(JwksParseTest, BadPem) {
  // U2lnbmF0dXJl is Base64 of "Signature"
  auto jwks = Jwks::createFrom("U2lnbmF0dXJl", Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), Status::JwksPemParseError);
}

TEST(JwksParseTest, GoodJwks) {
  const std::string jwks_text = R"(
      {
        "keys": [
          {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
            "n": "0YWnm_eplO9BFtXszMRQNL5UtZ8HJdTH2jK7vjs4XdLkPW7YBkkm_2xNgcaVpkW0VT2l4mU3KftR-6s3Oa5Rnz5BrWEUkCTVVolR7VYksfqIB2I_x5yZHdOiomMTcm3DheUUCgbJRv5OKRnNqszA4xHn3tA3Ry8VO3X7BgKZYAUh9fyZTFLlkeAh0-bLK5zvqCmKW5QgDIXSxUTJxPjZCgfx1vmAfGqaJb-nvmrORXQ6L284c73DUL7mnt6wj3H6tVqPKA27j56N0TB1Hfx4ja6Slr8S4EB3F1luYhATa1PKUSH8mYDW11HolzZmTQpRoLV8ZoHbHEaTfqX_aYahIw",
            "e": "AQAB"
          },
          {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
            "n": "qDi7Tx4DhNvPQsl1ofxxc2ePQFcs-L0mXYo6TGS64CY_2WmOtvYlcLNZjhuddZVV2X88m0MfwaSA16wE-RiKM9hqo5EY8BPXj57CMiYAyiHuQPp1yayjMgoE1P2jvp4eqF-BTillGJt5W5RuXti9uqfMtCQdagB8EC3MNRuU_KdeLgBy3lS3oo4LOYd-74kRBVZbk2wnmmb7IhP9OoLc1-7-9qU1uhpDxmE6JwBau0mDSwMnYDS4G_ML17dC-ZDtLd1i24STUw39KH0pcSdfFbL2NtEZdNeam1DDdk0iUtJSPZliUHJBI_pj8M-2Mn_oA8jBuI8YKwBqYkZCN1I95Q",
            "e": "AQAB"
         }
      ]
   }
)";

  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
  EXPECT_EQ(jwks->keys().size(), 2);

  EXPECT_EQ(jwks->keys()[0]->alg_, "RS256");
  EXPECT_EQ(jwks->keys()[0]->kid_, "62a93512c9ee4c7f8067b5a216dade2763d32a47");
  EXPECT_TRUE(jwks->keys()[0]->alg_specified_);
  EXPECT_TRUE(jwks->keys()[0]->kid_specified_);
  EXPECT_FALSE(jwks->keys()[0]->pem_format_);

  EXPECT_EQ(jwks->keys()[1]->alg_, "RS256");
  EXPECT_EQ(jwks->keys()[1]->kid_, "b3319a147514df7ee5e4bcdee51350cc890cc89e");
  EXPECT_TRUE(jwks->keys()[1]->alg_specified_);
  EXPECT_TRUE(jwks->keys()[1]->kid_specified_);
  EXPECT_FALSE(jwks->keys()[1]->pem_format_);
}

TEST(JwksParseTest, GoodEC) {
  // Public key JwkEC
  const std::string jwks_text = R"(
    {
       "keys": [
          {
             "kty": "EC",
             "crv": "P-256",
             "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
             "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8",
             "alg": "ES256",
             "kid": "abc"
          },
          {
             "kty": "EC",
             "crv": "P-256",
             "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
             "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8",
             "alg": "ES256",
             "kid": "xyz"
          },
          {
             "kty": "EC",
             "crv": "P-384",
             "x": "yY8DWcyWlrr93FTrscI5Ydz2NC7emfoKYHJLX2dr3cSgfw0GuxAkuQ5nBMJmVV5g",
             "y": "An5wVxEfksDOa_zvSHHGkeYJUfl8y11wYkOlFjBt9pOCw5-RlfZgPOa3pbmUquxZ",
             "alg": "ES384",
             "kid": "es384"
          },
          {
             "kty": "EC",
             "crv": "P-521",
             "x": "Abijiex7rz7t-_Zj_E6Oo0OXe9C_-MCSD-OWio15ATQGjH9WpbWjN62ZqrrU_nwJiqqwx6ZsYKhUc_J3PRaMbdVC",
             "y": "FxaljCIuoVEA7PJIaDPJ5ePXtZ0hkinT1B_bQ91mShCiR_43Whsn1P7Gz30WEnLuJs1SGVz1oT4lIRUYni2OfIk",
             "alg": "ES512",
             "kid": "es512"
          }
      ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
  EXPECT_EQ(jwks->keys().size(), 4);

  EXPECT_EQ(jwks->keys()[0]->alg_, "ES256");
  EXPECT_EQ(jwks->keys()[0]->kid_, "abc");
  EXPECT_EQ(jwks->keys()[0]->kty_, "EC");
  EXPECT_EQ(jwks->keys()[0]->crv_, "P-256");
  EXPECT_TRUE(jwks->keys()[0]->alg_specified_);
  EXPECT_TRUE(jwks->keys()[0]->kid_specified_);
  EXPECT_FALSE(jwks->keys()[0]->pem_format_);

  EXPECT_EQ(jwks->keys()[1]->alg_, "ES256");
  EXPECT_EQ(jwks->keys()[1]->kid_, "xyz");
  EXPECT_EQ(jwks->keys()[1]->kty_, "EC");
  EXPECT_EQ(jwks->keys()[1]->crv_, "P-256");
  EXPECT_TRUE(jwks->keys()[1]->alg_specified_);
  EXPECT_TRUE(jwks->keys()[1]->kid_specified_);
  EXPECT_FALSE(jwks->keys()[1]->pem_format_);

  EXPECT_EQ(jwks->keys()[2]->alg_, "ES384");
  EXPECT_EQ(jwks->keys()[2]->kid_, "es384");
  EXPECT_EQ(jwks->keys()[2]->kty_, "EC");
  EXPECT_EQ(jwks->keys()[2]->crv_, "P-384");
  EXPECT_TRUE(jwks->keys()[2]->alg_specified_);
  EXPECT_TRUE(jwks->keys()[2]->kid_specified_);
  EXPECT_FALSE(jwks->keys()[2]->pem_format_);

  EXPECT_EQ(jwks->keys()[3]->alg_, "ES512");
  EXPECT_EQ(jwks->keys()[3]->kid_, "es512");
  EXPECT_EQ(jwks->keys()[3]->kty_, "EC");
  EXPECT_EQ(jwks->keys()[3]->crv_, "P-521");
  EXPECT_TRUE(jwks->keys()[3]->alg_specified_);
  EXPECT_TRUE(jwks->keys()[3]->kid_specified_);
  EXPECT_FALSE(jwks->keys()[3]->pem_format_);
}

TEST(JwksParseTest, EmptyJwks) {
  auto jwks = Jwks::createFrom("", Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksParseError);
}

TEST(JwksParseTest, JwksNoKeys) {
  auto jwks = Jwks::createFrom("{}", Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksNoKeys);
}

TEST(JwksParseTest, JwksWrongKeys) {
  auto jwks = Jwks::createFrom(R"({"keys": 123})", Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksBadKeys);
}

TEST(JwksParseTest, JwksInvalidKty) {
  // Invalid kty field
  const std::string jwks_text = R"(
   {
      "keys": [
        {
           "kty": "XYZ",
           "crv": "P-256",
           "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
           "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8",
           "alg": "ES256",
           "kid": "abc"
        }
     ]
   }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksNotImplementedKty);
}

TEST(JwksParseTest, JwksMismatchKty1) {
  // kty doesn't match with alg
  const std::string jwks_text = R"(
     {
        "keys": [
           {
              "kty": "RSA",
              "alg": "ES256"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksRSAKeyBadAlg);
}

TEST(JwksParseTest, JwksMismatchKty2) {
  // kty doesn't match with alg
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "RS256"
           }
        ]
     }
)";

  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksECKeyBadAlg);
}

TEST(JwksParseTest, JwksECNoXY) {
  const std::string jwks_text = R"(
     {
        "keys": [
           {
              "kty": "EC",
              "alg": "ES256"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksECKeyMissingX);
}

TEST(JwksParseTest, JwksRSANoNE) {
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "RSA",
               "alg": "RS256"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksRSAKeyMissingN);
}

TEST(JwksParseTest, JwksECXYBadBase64) {
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "x": "~}}",
               "y": "92bCBTvMFQ8lKbS2MbgjT3Yf",
               "alg": "ES256"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksEcXorYBadBase64);
}

TEST(JwksParseTest, JwksECWrongXY) {
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k111",
               "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8111",
               "alg": "ES256"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksEcParseError);
}

TEST(JwksParseTest, JwksRSAWrongNE) {
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "RSA",
               "n": "EB54wykhS7YJFD6RYJNnwbW",
               "e": "92bCBTvMFQ8lKbS2MbgjT3YfmY",
               "alg": "RS256"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksRsaParseError);
}

TEST(JwksParseTest, JwksRSAInvalidN) {
  const std::string BadPublicKeyRSA =
      "{\n"
      " \"keys\": [\n"
      " {\n"
      " \"alg\": \"RS256\",\n"
      " \"kty\": \"RSA\",\n"
      " \"use\": \"sig\",\n"
      " \"x5c\": "
      "[\"MIIDjjCCAnYCCQDM2dGMrJDL3TANBgkqhkiG9w0BAQUFADCBiDEVMBMGA1UEAwwMd3d3L"
      "mRlbGwuY29tMQ0wCwYDVQQKDARkZWxsMQ0wCwYDVQQLDARkZWxsMRIwEAYDVQQHDAlCYW5nY"
      "WxvcmUxEjAQBgNVBAgMCUthcm5hdGFrYTELMAkGA1UEBhMCSU4xHDAaBgkqhkiG9w0BCQEWD"
      "WFiaGlAZGVsbC5jb20wHhcNMTkwNjI1MDcwNjM1WhcNMjAwNjI0MDcwNjM1WjCBiDEVMBMGA"
      "1UEAwwMd3d3LmRlbGwuY29tMQ0wCwYDVQQKDARkZWxsMQ0wCwYDVQQLDARkZWxsMRIwEAYDV"
      "QQHDAlCYW5nYWxvcmUxEjAQBgNVBAgMCUthcm5hdGFrYTELMAkGA1UEBhMCSU4xHDAaBgkqh"
      "kiG9w0BCQEWDWFiaGlAZGVsbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBA"
      "QDlE7W15NCXoIZX+"
      "uE7HF0LTnfgBpaqoYyQFDmVUNEd0WWV9nX04c3iyxZSpoTsoUZktNd0CUyC8oVRg2xxdPxA2"
      "aRVpNMwsDkuDnOZPNZZCS64QmMD7V5ebSAi4vQ7LH6zo9DCVwjzW10ZOZ3WHAyoKuNVGeb5w"
      "2+xDQM1mFqApy6KB7M/b3KG7cqpZfPn9Ebd1Uyk+8WY/"
      "IxJvb7EHt06Z+8b3F+LkRp7UI4ykkVkl3XaiBlG56ZyHfvH6R5Jy+"
      "8P0vl4wtX86N6MS48TZPhGAoo2KwWsOEGxve005ZK6LkHwxMsOD98yvLM7AG0SBxVF8O8KeZ"
      "/nbTP1oVSq6aEFAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGEhT6xuZqyZb/"
      "K6aI61RYy4tnR92d97H+zcL9t9/"
      "8FyH3qIAjIM9+qdr7dLLnVcNMmwiKzZpsBywno72z5gG4l6/TicBIJfI2BaG9JVdU3/"
      "wscPlqazwI/"
      "d1LvIkWSzrFQ2VdTPSYactPzGWddlx9QKU9cIKcNPcWdg0S0q1Khu8kejpJ+"
      "EUtSMc8OonFV99r1juFzVPtwGihuc6R7T/"
      "GnWgYLmhoCCaQKdLWn7FIyQH2WZ10CI6as+"
      "zKkylDkVnbsJYFabvbgRrNNl4RGXXm5D0lk9cwo1Srd28wEhi35b8zb1p0eTamS6qTpjHtc6"
      "DpgZK3MavFVdaFfR9bEYpHc=\"],\n"
      " \"n\": "
      "\"5RO1teTQl6CGV/"
      "rhOxxdC0534AaWqqGMkBQ5lVDRHdFllfZ19OHN4ssWUqaE7KFGZLTXdAlMgvKFUYNscXT8QN"
      "mkVaTTMLA5Lg5zmTzWWQkuuEJjA+1eXm0gIuL0Oyx+s6PQwlcI81tdGTmd1hwMqCrjVRnm+"
      "cNvsQ0DNZhagKcuigezP29yhu3KqWXz5/"
      "RG3dVMpPvFmPyMSb2+xB7dOmfvG9xfi5Eae1COMpJFZJd12ogZRuemch37x+"
      "keScvvD9L5eMLV/OjejEuPE2T4RgKKNisFrDhBsb3tNOWSui5B8MTLDg/"
      "fMryzOwBtEgcVRfDvCnmf520z9aFUqumhBQ\",\n"
      " \"e\": \"AQAB\",\n"
      " \"kid\": \"F46BB2F600BF3BBB53A324F12B290846\",\n"
      " \"x5t\": \"F46BB2F600BF3BBB53A324F12B290846\"\n"
      " }\n"
      " ]\n"
      "}";
  auto jwks = Jwks::createFrom(BadPublicKeyRSA, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksRsaParseError);
}

TEST(JwksParseTest, JwksECMatchAlgES256CrvP256) {
  // alg matches crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES256",
               "crv": "P-256",
               "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
               "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
}

TEST(JwksParseTest, JwksECMatchAlgES384CrvP384) {
  // alg matches crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES384",
               "crv": "P-384",
               "x": "yY8DWcyWlrr93FTrscI5Ydz2NC7emfoKYHJLX2dr3cSgfw0GuxAkuQ5nBMJmVV5g",
               "y": "An5wVxEfksDOa_zvSHHGkeYJUfl8y11wYkOlFjBt9pOCw5-RlfZgPOa3pbmUquxZ"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
}

TEST(JwksParseTest, JwksECMatchAlgES512CrvP521) {
  // alg matches crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES512",
               "crv": "P-521",
               "x": "Abijiex7rz7t-_Zj_E6Oo0OXe9C_-MCSD-OWio15ATQGjH9WpbWjN62ZqrrU_nwJiqqwx6ZsYKhUc_J3PRaMbdVC",
               "y": "FxaljCIuoVEA7PJIaDPJ5ePXtZ0hkinT1B_bQ91mShCiR_43Whsn1P7Gz30WEnLuJs1SGVz1oT4lIRUYni2OfIk"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
}

TEST(JwksParseTest, JwksECMissingBothAlgCrvES256) {
  // alg matches crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
               "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
}

TEST(JwksParseTest, JwksECMissingBothAlgES384) {
  // alg matches crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "x": "yY8DWcyWlrr93FTrscI5Ydz2NC7emfoKYHJLX2dr3cSgfw0GuxAkuQ5nBMJmVV5g",
               "y": "An5wVxEfksDOa_zvSHHGkeYJUfl8y11wYkOlFjBt9pOCw5-RlfZgPOa3pbmUquxZ"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  // It should fail since it is ES384, but we default to ES256
  EXPECT_EQ(jwks->getStatus(), Status::JwksEcParseError);
}

TEST(JwksParseTest, JwksECMismatchAlgCrv1) {
  // alg doesn't match with crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES256",
               "crv": "P-384"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksECKeyAlgNotCompatibleWithCrv);
}

TEST(JwksParseTest, JwkECMissingAlg) {
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "crv": "P-521",
               "kid": "sxG_WeuLxIKXoVit-8vyQf",
               "kty": "EC",
               "use": "sig",
               "x": "AG3w2vYgVbn4E27rkxZPUVrzLWhMctY5GOP6xygLLFwNRaoOx2gnlQPwAsEXHxz80u5lfmOms0pJSjuDrNqs5pB4",
               "y": "Ad0K-hbFmTVj3nMOw7jAdl21dlU35pG1g7h_Tswr0VYfxqg4ubIPyXrrtmlKH8q3c2Gqgq77Uq12qfcDE8zF2a4v"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
}

TEST(JwksParseTest, JwkECMissingCrv) {
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "alg": "ES512",
               "kid": "sxG_WeuLxIKXoVit-8vyQf",
               "kty": "EC",
               "use": "sig",
               "x": "AG3w2vYgVbn4E27rkxZPUVrzLWhMctY5GOP6xygLLFwNRaoOx2gnlQPwAsEXHxz80u5lfmOms0pJSjuDrNqs5pB4",
               "y": "Ad0K-hbFmTVj3nMOw7jAdl21dlU35pG1g7h_Tswr0VYfxqg4ubIPyXrrtmlKH8q3c2Gqgq77Uq12qfcDE8zF2a4v"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
}

TEST(JwksParseTest, JwksECMismatchAlgCrv2) {
  // alg doesn't match with crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES384",
               "crv": "P-521"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksECKeyAlgNotCompatibleWithCrv);
}

TEST(JwksParseTest, JwksECMismatchAlgCrv3) {
  // alg doesn't match with crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES512",
               "crv": "P-256"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksECKeyAlgNotCompatibleWithCrv);
}

TEST(JwksParseTest, JwksECNotSupportedAlg) {
  // alg doesn't match with crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES1024",
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksECKeyAlgOrCrvUnsupported);
}

TEST(JwksParseTest, JwksECNotSupportedCrv) {
  // alg doesn't match with crv
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "crv": "P-1024"
           }
        ]
     }
)";
  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::JwksECKeyAlgOrCrvUnsupported);
}

TEST(JwksParseTest, JwksECUnspecifiedCrv) {
  // crv determined from alg
  const std::string jwks_text = R"(
     {
        "keys": [
           {
               "kty": "EC",
               "alg": "ES256",
               "x": "EB54wykhS7YJFD6RYJNnwbWEz3cI7CF5bCDTXlrwI5k",
               "y": "92bCBTvMFQ8lKbS2MbgjT3YfmYo6HnPEE2tsAqWUJw8"
           },
           {
               "kty": "EC",
               "alg": "ES384",
               "x": "yY8DWcyWlrr93FTrscI5Ydz2NC7emfoKYHJLX2dr3cSgfw0GuxAkuQ5nBMJmVV5g",
               "y": "An5wVxEfksDOa_zvSHHGkeYJUfl8y11wYkOlFjBt9pOCw5-RlfZgPOa3pbmUquxZ"
           },
           {
               "kty": "EC",
               "alg": "ES512",
               "x": "Abijiex7rz7t-_Zj_E6Oo0OXe9C_-MCSD-OWio15ATQGjH9WpbWjN62ZqrrU_nwJiqqwx6ZsYKhUc_J3PRaMbdVC",
               "y": "FxaljCIuoVEA7PJIaDPJ5ePXtZ0hkinT1B_bQ91mShCiR_43Whsn1P7Gz30WEnLuJs1SGVz1oT4lIRUYni2OfIk"
           }
        ]
     }
)";

  auto jwks = Jwks::createFrom(jwks_text, Jwks::JWKS);
  EXPECT_EQ(jwks->getStatus(), Status::Ok);
  EXPECT_EQ(jwks->keys().size(), 3);

  EXPECT_EQ(jwks->keys()[0]->alg_, "ES256");
  EXPECT_EQ(jwks->keys()[0]->crv_, "P-256");
  EXPECT_TRUE(jwks->keys()[0]->alg_specified_);

  EXPECT_EQ(jwks->keys()[1]->alg_, "ES384");
  EXPECT_EQ(jwks->keys()[1]->crv_, "P-384");
  EXPECT_TRUE(jwks->keys()[1]->alg_specified_);

  EXPECT_EQ(jwks->keys()[2]->alg_, "ES512");
  EXPECT_EQ(jwks->keys()[2]->crv_, "P-521");
  EXPECT_TRUE(jwks->keys()[2]->alg_specified_);
}

}  // namespace
}  // namespace jwt_verify
}  // namespace google
