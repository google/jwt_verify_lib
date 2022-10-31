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

#include "jwt_verify_lib/status.h"

#include "absl/container/flat_hash_map.h"

#include <iostream>
#include <map>
#include <string>

namespace google {
namespace jwt_verify {

std::string getStatusString(Status status) {
  static const auto* status_str_map = new absl::flat_hash_map<
      Status, absl::string_view>({
      {Status::Ok, "OK"},
      {Status::JwtMissed, "Jwt is missing"},
      {Status::JwtNotYetValid, "Jwt not yet valid"},
      {Status::JwtExpired, "Jwt is expired"},
      {Status::JwtBadFormat,
       "Jwt is not in the form of Header.Payload.Signature with two dots "
       "and 3 sections"},
      {Status::JwtHeaderParseErrorBadBase64,
       "Jwt header is an invalid Base64url encoded"},
      {Status::JwtHeaderParseErrorBadJson, "Jwt header is an invalid JSON"},
      {Status::JwtHeaderBadAlg,
       "Jwt header [alg] field is required and must be a string"},
      {Status::JwtHeaderNotImplementedAlg, "Jwt header [alg] is not supported"},
      {Status::JwtHeaderBadKid, "Jwt header [kid] field is not a string"},
      {Status::JwtPayloadParseErrorBadBase64,
       "Jwt payload is an invalid Base64url encoded"},
      {Status::JwtEd25519SignatureWrongLength,
       "Jwt ED25519 signature is wrong length"},
      {Status::JwtPayloadParseErrorBadJson, "Jwt payload is an invalid JSON"},
      {Status::JwtPayloadParseErrorIssNotString,
       "Jwt payload [iss] field is not a string"},
      {Status::JwtPayloadParseErrorSubNotString,
       "Jwt payload [sub] field is not a string"},
      {Status::JwtPayloadParseErrorIatNotInteger,
       "Jwt payload [iat] field is not an integer"},
      {Status::JwtPayloadParseErrorIatNotPositive,
       "Jwt payload [iat] field is not a positive integer"},
      {Status::JwtPayloadParseErrorNbfNotInteger,
       "Jwt payload [nbf] field is not an integer"},
      {Status::JwtPayloadParseErrorNbfNotPositive,
       "Jwt payload [nbf] field is not a positive integer"},
      {Status::JwtPayloadParseErrorExpNotInteger,
       "Jwt payload [exp] field is not an integer"},
      {Status::JwtPayloadParseErrorExpNotPositive,
       "Jwt payload [exp] field is not a positive integer"},
      {Status::JwtPayloadParseErrorJtiNotString,
       "Jwt payload [jti] field is not a string"},
      {Status::JwtPayloadParseErrorAudNotString,
       "Jwt payload [aud] field is not a string or string list"},
      {Status::JwtSignatureParseErrorBadBase64,
       "Jwt signature is an invalid Base64url encoded"},
      {Status::JwtUnknownIssuer, "Jwt issuer is not configured"},
      {Status::JwtAudienceNotAllowed, "Audiences in Jwt are not allowed"},
      {Status::JwtVerificationFail, "Jwt verification fails"},
      {Status::JwtMultipleTokens, "Found multiple Jwt tokens"},

      {Status::JwksParseError, "Jwks is an invalid JSON"},
      {Status::JwksNoKeys, "Jwks does not have [keys] field"},
      {Status::JwksBadKeys, "[keys] in Jwks is not an array"},
      {Status::JwksNoValidKeys, "Jwks doesn't have any valid public key"},
      {Status::JwksKidAlgMismatch,
       "Jwks doesn't have key to match kid or alg from Jwt"},
      {Status::JwksRsaParseError,
       "Jwks RSA [n] or [e] field is missing or has a parse error"},
      {Status::JwksEcCreateKeyFail, "Jwks EC create key fail"},
      {Status::JwksEcXorYBadBase64,
       "Jwks EC [x] or [y] field is an invalid Base64."},
      {Status::JwksEcParseError,
       "Jwks EC [x] and [y] fields have a parse error."},
      {Status::JwksOctBadBase64, "Jwks Oct key is an invalid Base64"},
      {Status::JwksOKPXBadBase64, "Jwks OKP [x] field is an invalid Base64."},
      {Status::JwksOKPXWrongLength, "Jwks OKP [x] field is wrong length."},
      {Status::JwksFetchFail, "Jwks remote fetch is failed"},

      {Status::JwksMissingKty, "[kty] is missing in [keys]"},
      {Status::JwksBadKty, "[kty] is bad in [keys]"},
      {Status::JwksNotImplementedKty, "[kty] is not supported in [keys]"},

      {Status::JwksRSAKeyBadAlg,
       "[alg] is not started with [RS] or [PS] for an RSA key"},
      {Status::JwksRSAKeyMissingN, "[n] field is missing for a RSA key"},
      {Status::JwksRSAKeyBadN, "[n] field is not string for a RSA key"},
      {Status::JwksRSAKeyMissingE, "[e] field is missing for a RSA key"},
      {Status::JwksRSAKeyBadE, "[e] field is not string for a RSA key"},

      {Status::JwksECKeyBadAlg, "[alg] is not started with [ES] for an EC key"},
      {Status::JwksECKeyBadCrv, "[crv] field is not string for an EC key"},
      {Status::JwksECKeyAlgOrCrvUnsupported,
       "[crv] or [alg] field is not supported for an EC key"},
      {Status::JwksECKeyAlgNotCompatibleWithCrv,
       "[crv] field specified is not compatible with [alg] for an EC key"},
      {Status::JwksECKeyMissingX, "[x] field is missing for an EC key"},
      {Status::JwksECKeyBadX, "[x] field is not string for an EC key"},
      {Status::JwksECKeyMissingY, "[y] field is missing for an EC key"},
      {Status::JwksECKeyBadY, "[y] field is not string for an EC key"},

      {Status::JwksHMACKeyBadAlg,
       "[alg] does not start with [HS] for an HMAC key"},
      {Status::JwksHMACKeyMissingK, "[k] field is missing for an HMAC key"},
      {Status::JwksHMACKeyBadK, "[k] field is not string for an HMAC key"},

      {Status::JwksOKPKeyBadAlg, "[alg] is not [EdDSA] for an OKP key"},
      {Status::JwksOKPKeyMissingCrv, "[crv] field is missing for an OKP key"},
      {Status::JwksOKPKeyBadCrv, "[crv] field is not string for an OKP key"},
      {Status::JwksOKPKeyCrvUnsupported,
       "[crv] field is not supported for an OKP key"},
      {Status::JwksOKPKeyMissingX, "[x] field is missing for an OKP key"},
      {Status::JwksOKPKeyBadX, "[x] field is not string for an OKP key"},

      {Status::JwksX509BioWriteError,
       "X509 parse pubkey internal fails: memory allocation"},
      {Status::JwksX509ParseError, "X509 parse pubkey fails"},
      {Status::JwksX509GetPubkeyError,
       "X509 parse pubkey internal fails: get pubkey"},

      {Status::JwksPemNotImplementedKty, "PEM Key type is not supported"},
      {Status::JwksPemBadBase64, "PEM pubkey parse fails"},
      {Status::JwksPemGetRawEd25519Error, "PEM failed to get raw ED25519 key"},

      {Status::JwksBioAllocError,
       "Failed to create BIO due to memory allocation failure"},
  });

  const auto& it = status_str_map->find(status);
  return it == status_str_map->end() ? "" : std::string(it->second);
}

}  // namespace jwt_verify
}  // namespace google
