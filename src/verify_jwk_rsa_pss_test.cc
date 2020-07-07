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

#include "gtest/gtest.h"
#include "jwt_verify_lib/verify.h"
#include "src/test_common.h"

namespace google {
namespace jwt_verify {
namespace {

// The following is the jwks from querying a private temporary instance of keycloak at
// https://keycloak.localhost/auth/realms/applications/protocol/openid-connect/certs

const std::string PublicKeyRSAPSS = R"(
{
  "keys": [
    {
      "kid": "RGlV9a54XdAsuiYUDkQ0hDkiSZ92TJCgneh7-HvN-sk",
      "kty": "RSA",
      "alg": "PS384",
      "use": "sig",
      "n": "8logDcIilAXYJ2kNOrUIAVrWg3g-i1EUsWzEwAV3WT9NNwisUsljdyK3OOxy8yhbWyunxia-4Qo8nCIjURfLn0XoJyozCsruTWuvv2nvWx380zDD5gN-RK0kab_UWOV_zkr9YhBYd2PUB-sCcEwDKj8uHZrJ2CvXvxt2LV8_l_kwlCEDS_q97eEqvxhvYFF8DVo_AGABoK6fU1urn7X-GQcClgOEI8qKho-FU0RPJM80pnmCVds7oP2NYHSnAbkxltiB2cU1qazs21A52obU5zemUwJcdEGpykBKgc_aKaxkusLs2O0xWvnDbgXvboqb_0UhZPWNILZYK09jYCFobQ",
      "e": "AQAB",
      "x5c": [
        "MIICpzCCAY8CBgFzHKZh6TANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxhcHBsaWNhdGlvbnMwHhcNMjAwNzA1MDE0MzUyWhcNMzAwNzA1MDE0NTMyWjAXMRUwEwYDVQQDDAxhcHBsaWNhdGlvbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDyWiANwiKUBdgnaQ06tQgBWtaDeD6LURSxbMTABXdZP003CKxSyWN3Irc47HLzKFtbK6fGJr7hCjycIiNRF8ufRegnKjMKyu5Na6+/ae9bHfzTMMPmA35ErSRpv9RY5X/OSv1iEFh3Y9QH6wJwTAMqPy4dmsnYK9e/G3YtXz+X+TCUIQNL+r3t4Sq/GG9gUXwNWj8AYAGgrp9TW6uftf4ZBwKWA4QjyoqGj4VTRE8kzzSmeYJV2zug/Y1gdKcBuTGW2IHZxTWprOzbUDnahtTnN6ZTAlx0QanKQEqBz9oprGS6wuzY7TFa+cNuBe9uipv/RSFk9Y0gtlgrT2NgIWhtAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMaFjwzA+74wY+2YjsMk79IpvDV3Kke7hBThz+9+KT8u2cCX1fUucZemk5vNfLbv+Swhjs+Psuhim1mXxqfyNeSPrIznWAQDSUIW5c3SuJtIOXbfXjIoeK7QW4yhv4NsQBnXd0o6UncvlSZvFxQCMDqGrybOim2O93nM7p3udE2c08tAZ/XRFrxgENvuO3XGAg5EIiUEbHjtOgpjGwkxDfvOm0C4giaaHbUEarzK0olAExtKENwa9AKsxnckMH/kWNBY6ohYSJ7DojRUY84bKTWWFx8Krj0kzjNkbadrdAya8YoRp4IRqjZ9cA9i+yIlN1ulhL9GGq4JDHqTFaoBxiQ="
      ],
      "x5t": "6mK6ZUgfCVv2sm7GVsDR_tdPjjE",
      "x5t#S256": "PJYSXCbyowmimYVC41vPKlZyUfmqcGNo6Cfba4y8pkE"
    },
    {
      "kid": "u_ZZAorrQhtL2MA-bWkZ0qpzjia4D3u6QUvBRscHLrg",
      "kty": "RSA",
      "alg": "PS512",
      "use": "sig",
      "n": "0k2d9uo6k1luw7VpgeZuf4xIlhpp_pPndYjHCZBhSmXsXN7lV-HhYE3Vv2WurMT32HrOJVm4zJWbQOOFG2LD8Byw1sKzZWoS_wwFUWdeTzw43JniK-PYDY5sOM5sn6uGtfLNzm0fO0gkhLMf-dgodimA7dw_4kFqIYP9VNJOi3Pw3XI0uAuK1X7_eJ7mzWlCC8ERT0iJELKqC1Hx8Ub13SeTaFvPoguvx08END87WUbkdp4e4N16d_wVUWuutidY2HkjcklNhUWTc0BSST89TyKwwXwrXqY7_Ka14pjo8H-s6nT1ns80LiTjvjgzyeMRbptOYmgxlmYL0AXI07hbZw",
      "e": "AQAB",
      "x5c": [
        "MIICpzCCAY8CBgFzHKaU5jANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxhcHBsaWNhdGlvbnMwHhcNMjAwNzA1MDE0NDA1WhcNMzAwNzA1MDE0NTQ1WjAXMRUwEwYDVQQDDAxhcHBsaWNhdGlvbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSTZ326jqTWW7DtWmB5m5/jEiWGmn+k+d1iMcJkGFKZexc3uVX4eFgTdW/Za6sxPfYes4lWbjMlZtA44UbYsPwHLDWwrNlahL/DAVRZ15PPDjcmeIr49gNjmw4zmyfq4a18s3ObR87SCSEsx/52Ch2KYDt3D/iQWohg/1U0k6Lc/DdcjS4C4rVfv94nubNaUILwRFPSIkQsqoLUfHxRvXdJ5NoW8+iC6/HTwQ0PztZRuR2nh7g3Xp3/BVRa662J1jYeSNySU2FRZNzQFJJPz1PIrDBfCtepjv8prXimOjwf6zqdPWezzQuJOO+ODPJ4xFum05iaDGWZgvQBcjTuFtnAgMBAAEwDQYJKoZIhvcNAQELBQADggEBALyEXqK3BYwVU/7o8+wfDwOJ2nk9OmoGIu3hu6gwqC92DOXClus11UGHKsfhhYlQdzdBpNRD5hjabqaEpCoqF4HwzIWL+Pc08hnnP1IsxkAZdKicKLeFE6BwldK/RYK5vuNXjO824xGnTJuIEApWD2lWf7T3Ndyve14vx1B+6NPmazXPHcSbDN+06bXg8YeZVMnBqRYVBCxo5IoEwP2kJC/F3RbYJTF8QV2/AnwA/Bt1/rl6Y9MPqCwntyfrxq26Bwlpf9vC1dwRK45Tgv9c94/rD1Xax3MPQhhnCo+6H9UWSe/mIdPC2jPifcYJGujPpbbcp23fBOig+FwY6OZl1oo="
      ],
      "x5t": "YVSZ0gbRsdQ2ItVwc00GynAyFwk",
      "x5t#S256": "ZOJz7HKW1fQVb46QI0Ymw7v4u1mfRmzDJmOp3zUMpt4"
    },
    {
      "kid": "4hmO65bbc7IVI-3PfA2emAlO0qhv4rB__yw8BPQ58q8",
      "kty": "RSA",
      "alg": "PS256",
      "use": "sig",
      "n": "vz40nPlC2XsAGbqfp3S4nyl2G1iMFER1l_I4k7gfC-87UWu2-a7BZQHb646WmSXu8xFzu0x5FFTFmu_v3Aj1NAcdYbz09UypSxfH--aw7ATiSWL26jHixFP4l6miJxaXV-rlp9qFSO--1JRnlvYrt6M5mQI0ZvN8EahAVXIHNtDMZYu0HYwwL7j45gjF9o9kDbfMSPr8Oni0QC2tTcCg623OlNqrJZFT4YNJ8A1nRfwGwBLFp5pxpK9ZCekQVhBpZNUrlLB5uDaB5H9lwFKslbHC-HKlJbfZZg16j6tlQTgw6dnKNo5LPrZ4TeSUyuoudzZSpZo4dyFsasTfWYTSLQ",
      "e": "AQAB",
      "x5c": [
        "MIICpzCCAY8CBgFzHIdU1jANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxhcHBsaWNhdGlvbnMwHhcNMjAwNzA1MDEwOTU3WhcNMzAwNzA1MDExMTM3WjAXMRUwEwYDVQQDDAxhcHBsaWNhdGlvbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/PjSc+ULZewAZup+ndLifKXYbWIwURHWX8jiTuB8L7ztRa7b5rsFlAdvrjpaZJe7zEXO7THkUVMWa7+/cCPU0Bx1hvPT1TKlLF8f75rDsBOJJYvbqMeLEU/iXqaInFpdX6uWn2oVI777UlGeW9iu3ozmZAjRm83wRqEBVcgc20Mxli7QdjDAvuPjmCMX2j2QNt8xI+vw6eLRALa1NwKDrbc6U2qslkVPhg0nwDWdF/AbAEsWnmnGkr1kJ6RBWEGlk1SuUsHm4NoHkf2XAUqyVscL4cqUlt9lmDXqPq2VBODDp2co2jks+tnhN5JTK6i53NlKlmjh3IWxqxN9ZhNItAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEhiswSA4BBd9ka473JMX27y+4ZyxitUWi9ARhloiPtE7b+HVsRd6febjPlwMZJ/x7c5lRrQXEGCtJdHcVf2JybNo9bAPSsnmGAD9I+x5GyJljgRuItcfIJ3ALV7LqMbFPZ7cO6jB9hzYtjzECRN0+hJKSZm99kpau2sI8C1FkT+aSK7+j0jGagYwfI8hG7SV1IKQgTxtGZSpFgn2mi60TYsnLt2JYKSACq5hZykO7BPxnTK0sAK9ue34ddEuVe6L1wxDv44PME2dZwRmCRT5d7qj8lO4n2VYqBbc90ME6yAeRIhYRZSrHFTE2Wkufi+21HXIB63dKoYqiPe3y/GZno="
      ],
      "x5t": "5lmEYc56y8EeBpHsP1-LO8M0W2c",
      "x5t#S256": "oC0EpmLVEv1CptAVxKT9uVpC975xKlu3xOrhh8RTNy4"
    }
  ]
}
)";

// JWT with correct kid
// Header:
// {
//   "alg": "PS256",
//   "typ": "JWT",
//   "kid": "4hmO65bbc7IVI-3PfA2emAlO0qhv4rB__yw8BPQ58q8"
// }
// Payload:
// {
//   "exp": 1593912811,
//   "iat": 1593912511,
//   "jti": "3c9ee909-3ca5-4587-8c0b-700cb4cb8e62",
//   "iss": "https://keycloak.localhost/auth/realms/applications",
//   "sub": "c3cfd999-ca22-4080-9863-277427db4321",
//   "typ": "Bearer",
//   "azp": "foo",
//   "session_state": "de37ba9c-4b3a-4250-a89b-da81928fcf9b",
//   "acr": "1",
//   "scope": "email profile",
//   "email_verified": false,
//   "name": "User Zero",
//   "preferred_username": "user0",
//   "given_name": "User",
//   "family_name": "Zero",
//   "email": "user0@mail.com"
// }
const std::string JwtTextWithCorrectKid =
    "eyJhbGciOiJQUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0aG1PNjViYmM3SVZJLTNQ"
    "ZkEyZW1BbE8wcWh2NHJCX195dzhCUFE1OHE4In0."
    "eyJleHAiOjE1OTM5MTI4MTEsImlhdCI6MTU5MzkxMjUxMSwianRpIjoiM2M5ZWU5MDktM2Nh"
    "NS00NTg3LThjMGItNzAwY2I0Y2I4ZTYyIiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay5sb2Nh"
    "bGhvc3QvYXV0aC9yZWFsbXMvYXBwbGljYXRpb25zIiwic3ViIjoiYzNjZmQ5OTktY2EyMi00"
    "MDgwLTk4NjMtMjc3NDI3ZGI0MzIxIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZm9vIiwic2Vz"
    "c2lvbl9zdGF0ZSI6ImRlMzdiYTljLTRiM2EtNDI1MC1hODliLWRhODE5MjhmY2Y5YiIsImFj"
    "ciI6IjEiLCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2Us"
    "Im5hbWUiOiJVc2VyIFplcm8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VyMCIsImdpdmVu"
    "X25hbWUiOiJVc2VyIiwiZmFtaWx5X25hbWUiOiJaZXJvIiwiZW1haWwiOiJ1c2VyMEBtYWls"
    "LmNvbSJ9."
    "fas6TkXZ97K1d8tTMCEFDcG-MupI-BwGn0UZD8riwmbLf5xmDPaoZwmJ3k-szVo-oJMfMZbr"
    "VAI8xQwg4Z7bQvd3I9WM6XPsu1_gKnkc2EOATgkdpDg5rWOPSZCFLUD_bqsoPQrfc2C1-UKs"
    "VOwUkXEH6rEIlOvngqQWNJjtbkvsS2N_3kNAgaD8cELT5mxmM4vGZn14OHmXHJBIW9pHJU64"
    "tA0sDcexoylL7xB_E1XTs3St0sYyq_pz9920vHScr9KXQ3y9k-fbPvgBs2gGY0iK63E0lEwD"
    "fRWY4Za6RRqymammehv7ZiE4HjDy5Q_AdLGdRefrTxtiQrHIThLqAw";


class VerifyJwkRsaPssTest : public testing::Test {
 protected:
  void SetUp() {
    jwks_ = Jwks::createFrom(PublicKeyRSAPSS, Jwks::Type::JWKS);
    EXPECT_EQ(jwks_->getStatus(), Status::Ok);
  }

  JwksPtr jwks_;
};


TEST_F(VerifyJwkRsaPssTest, CorrectKidOK) {
  Jwt jwt;
  EXPECT_EQ(jwt.parseFromString(JwtTextWithCorrectKid), Status::Ok);
  EXPECT_EQ(verifyJwt(jwt, *jwks_, 1), Status::Ok);

  fuzzJwtSignature(jwt, [this](const Jwt& jwt) {
    EXPECT_EQ(verifyJwt(jwt, *jwks_, 1), Status::JwtVerificationFail);
  });
}

}  // namespace
}  // namespace jwt_verify
}  // namespace google
