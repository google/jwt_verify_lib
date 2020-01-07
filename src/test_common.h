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

#include <functional>
#include "jwt_verify_lib/jwt.h"

namespace google {
namespace jwt_verify {

/**
 * This function fuzz the signature in two loops
 */
void fuzzJwtSignature(const Jwt& jwt,
                      std::function<void(const Jwt& jwt)> test_fn) {
  // alter 1 bit
  for (size_t b = 0; b < jwt.signature_.size(); ++b) {
    for (int bit = 0; bit < 8; ++bit) {
      Jwt fuzz_jwt(jwt);
      unsigned char bb = fuzz_jwt.signature_[b];
      bb ^= (unsigned char)(1 << bit);
      fuzz_jwt.signature_[b] = (char)bb;
      test_fn(fuzz_jwt);
    }
  }

  // truncate bytes
  for (size_t count = 1; count < jwt.signature_.size(); ++count) {
    Jwt fuzz_jwt(jwt);
    fuzz_jwt.signature_ = jwt.signature_.substr(0, count);
    test_fn(fuzz_jwt);
  }
}

// copy from ESP:
// https://github.com/cloudendpoints/esp/src/api_manager/auth/lib/auth_jwt_validator_test.cc
const char kPublicKeyX509[] =
    "{\"62a93512c9ee4c7f8067b5a216dade2763d32a47\": \"-----BEGIN "
    "CERTIFICATE-----"
    "\\nMIIDYDCCAkigAwIBAgIIEzRv3yOFGvcwDQYJKoZIhvcNAQEFBQAwUzFRME8GA1UE\\nAxNI"
    "NjI4NjQ1NzQxODgxLW5vYWJpdTIzZjVhOG04b3ZkOHVjdjY5OGxqNzh2djBs\\nLmFwcHMuZ29"
    "vZ2xldXNlcmNvbnRlbnQuY29tMB4XDTE1MDkxMTIzNDg0OVoXDTI1\\nMDkwODIzNDg0OVowUz"
    "FRME8GA1UEAxNINjI4NjQ1NzQxODgxLW5vYWJpdTIzZjVh\\nOG04b3ZkOHVjdjY5OGxqNzh2d"
    "jBsLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
    "MIIBCgKCAQEA0YWnm/eplO9BFtXszMRQ\\nNL5UtZ8HJdTH2jK7vjs4XdLkPW7YBkkm/"
    "2xNgcaVpkW0VT2l4mU3KftR+6s3Oa5R\\nnz5BrWEUkCTVVolR7VYksfqIB2I/"
    "x5yZHdOiomMTcm3DheUUCgbJRv5OKRnNqszA\\n4xHn3tA3Ry8VO3X7BgKZYAUh9fyZTFLlkeA"
    "h0+bLK5zvqCmKW5QgDIXSxUTJxPjZ\\nCgfx1vmAfGqaJb+"
    "nvmrORXQ6L284c73DUL7mnt6wj3H6tVqPKA27j56N0TB1Hfx4\\nja6Slr8S4EB3F1luYhATa1"
    "PKUSH8mYDW11HolzZmTQpRoLV8ZoHbHEaTfqX/"
    "aYah\\nIwIDAQABozgwNjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/"
    "wQEAwIHgDAWBgNVHSUB\\nAf8EDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOCAQEAP4gk"
    "DCrPMI27/"
    "QdN\\nwW0mUSFeDuM8VOIdxu6d8kTHZiGa2h6nTz5E+"
    "twCdUuo6elGit3i5H93kFoaTpex\\nj/eDNoULdrzh+cxNAbYXd8XgDx788/"
    "jm06qkwXd0I5s9KtzDo7xxuBCyGea2LlpM\\n2HOI4qFunjPjFX5EFdaT/Rh+qafepTKrF/"
    "GQ7eGfWoFPbZ29Hs5y5zATJCDkstkY\\npnAya8O8I+"
    "tfKjOkcra9nOhtck8BK94tm3bHPdL0OoqKynnoRCJzN5KPlSGqR/h9\\nSMBZzGtDOzA2sX/"
    "8eyU6Rm4MV6/1/53+J6EIyarR5g3IK1dWmz/YT/YMCt6LhHTo\\n3yfXqQ==\\n-----END "
    "CERTIFICATE-----\\n\",\"b3319a147514df7ee5e4bcdee51350cc890cc89e\": "
    "\"-----BEGIN "
    "CERTIFICATE-----"
    "\\nMIIDYDCCAkigAwIBAgIICjE9gZxAlu8wDQYJKoZIhvcNAQEFBQAwUzFRME8GA1UE\\nAxNI"
    "NjI4NjQ1NzQxODgxLW5vYWJpdTIzZjVhOG04b3ZkOHVjdjY5OGxqNzh2djBs\\nLmFwcHMuZ29"
    "vZ2xldXNlcmNvbnRlbnQuY29tMB4XDTE1MDkxMzAwNTAyM1oXDTI1\\nMDkxMDAwNTAyM1owUz"
    "FRME8GA1UEAxNINjI4NjQ1NzQxODgxLW5vYWJpdTIzZjVh\\nOG04b3ZkOHVjdjY5OGxqNzh2d"
    "jBsLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
    "MIIBCgKCAQEAqDi7Tx4DhNvPQsl1ofxx\\nc2ePQFcs+L0mXYo6TGS64CY/"
    "2WmOtvYlcLNZjhuddZVV2X88m0MfwaSA16wE+"
    "RiK\\nM9hqo5EY8BPXj57CMiYAyiHuQPp1yayjMgoE1P2jvp4eqF+"
    "BTillGJt5W5RuXti9\\nuqfMtCQdagB8EC3MNRuU/"
    "KdeLgBy3lS3oo4LOYd+74kRBVZbk2wnmmb7IhP9OoLc\\n1+7+"
    "9qU1uhpDxmE6JwBau0mDSwMnYDS4G/"
    "ML17dC+ZDtLd1i24STUw39KH0pcSdf\\nFbL2NtEZdNeam1DDdk0iUtJSPZliUHJBI/"
    "pj8M+2Mn/"
    "oA8jBuI8YKwBqYkZCN1I9\\n5QIDAQABozgwNjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/"
    "wQEAwIHgDAWBgNVHSUB\\nAf8EDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOCAQEAHSPR"
    "7fDAWyZ825IZ\\n86hEsQZCvmC0QbSzy62XisM/uHUO75BRFIAvC+zZAePCcNo/"
    "nh6FtEM19wZpxLiK\\n0m2nqDMpRdw3Qt6BNhjJMozTxA2Xdipnfq+fGpa+"
    "bMkVpnRZ53qAuwQpaKX6vagr\\nj83Bdx2b5WPQCg6xrQWsf79Vjj2U1hdw7+"
    "klcF7tLef1p8qA/ezcNXmcZ4BpbpaO\\nN9M4/kQOA3Y2F3ISAaOJzCB25F259whjW+Uuqd/"
    "L9Lb4gPPSUMSKy7Zy4Sn4il1U\\nFc94Mi9j13oeGvLOduNOStGu5XROIxDtCEjjn2y2SL2bPw"
    "0qAlIzBeniiApkmYw/\\no6OLrg==\\n-----END CERTIFICATE-----\\n\"}";

}  // namespace jwt_verify
}  // namespace google
