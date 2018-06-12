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

#include <map>

#include "jwt_verify_lib/status.h"

namespace google {
namespace jwt_verify {

std::string getStatusString(Status status) {
  static std::map<Status, std::string> table = {
      {Status::Ok, "OK"},

      {Status::JwtMissed, "Jwt missing"},
      {Status::JwtExpired, "Jwt expired"},
      {Status::JwtBadFormat,
       "Jwt is not in the form of Header.Payload.Signature"},
      {Status::JwtHeaderParseError,
       "Jwt header is an invalid Base64url input or an invalid JSON"},
      {Status::JwtHeaderBadAlg, "Jwt header [alg] field is not a string"},
      {Status::JwtHeaderNotImplementedAlg,
       "Jwt header [alg] field value is invalid"},
      {Status::JwtHeaderBadKid, "Jwt header [kid] field is not a string"},
      {Status::JwtPayloadParseError,
       "Jwt payload is an invalid Base64url input or an invalid JSON"},
      {Status::JwtSignatureParseError,
       "Jwt signature is an invalid Base64url input"},
      {Status::JwtUnknownIssuer, "Jwt issuer is not configured"},
      {Status::JwtAudienceNotAllowed, "Audience in Jwt is not allowed"},
      {Status::JwtVerificationFail, "Jwt verification fails"},

      {Status::JwksParseError, "Jwks is an invalid JSON"},
      {Status::JwksNoKeys, "Jwks does not have [keys] field"},
      {Status::JwksBadKeys, "[keys] in Jwks is not an array"},
      {Status::JwksNoValidKeys, "Jwks doesn't have any valid public key"},
      {Status::JwksKidAlgMismatch,
       "Jwks doesn't have key to match kid or alg from Jwt"},
      {Status::JwksPemBadBase64, "Jwks PEM public key is an invalid Base64"},
      {Status::JwksPemParseError, "Jwks PEM public key parse error"},
      {Status::JwksRsaParseError,
       "Jwks RSA [n] or [e] field is missing or has a parse error"},
      {Status::JwksEcCreateKeyFail, "Jwks EC create key fail"},
      {Status::JwksEcParseError,
       "Jwks EC [x] or [y] field is missing or has a parse error."},
      {Status::JwksFetchFail, "Jwks fetch fail"},

      {Status::JwksMissingKty, "[kty] is missing in [keys]"},
      {Status::JwksBadKty, "[kty] is missing in [keys]"},
      {Status::JwksNotImplementedKty, "[kty] is not supported in [keys]"},

      {Status::JwksRSAKeyBadAlg,
       "[alg] is not started with [RS] for a RSA key"},
      {Status::JwksRSAKeyMissingN, "[n] field is missing for a RSA key"},
      {Status::JwksRSAKeyBadN, "[n] field is not string for a RSA key"},
      {Status::JwksRSAKeyMissingE, "[e] field is missing for a RSA key"},
      {Status::JwksRSAKeyBadE, "[e] field is not string for a RSA key"},

      {Status::JwksECKeyBadAlg, "[alg] is not [ES256] for an EC key"},
      {Status::JwksECKeyMissingX, "[x] field is missing for an EC key"},
      {Status::JwksECKeyBadX, "[x] field is not string for an EC key"},
      {Status::JwksECKeyMissingY, "[y] field is missing for an EC key"},
      {Status::JwksECKeyBadY, "[y] field is not string for an EC key"},
  };
  return table[status];
}

}  // namespace jwt_verify
}  // namespace google
