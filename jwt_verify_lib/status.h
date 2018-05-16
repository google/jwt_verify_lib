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

#include <string>

namespace google {
namespace jwt_verify {

/**
 * Define the Jwt verification error status.
 */
enum class Status {
  Ok = 0,

  // Jwt errors:

  // Jwt missing.
  JwtMissed = 1,

  // Jwt expired.
  JwtExpired = 2,

  // JWT is not in the form of Header.Payload.Signature
  JwtBadFormat = 3,

  // Jwt header is an invalid Base64url input or an invalid JSON.
  JwtHeaderParseError = 4,

  // "alg" in the header is not a string.
  JwtHeaderBadAlg = 6,

  // Value of "alg" in the header is invalid.
  JwtHeaderNotImplementedAlg = 7,

  // "kid" in the header is not a string.
  JwtHeaderBadKid = 8,

  // Jwt payload is an invalid Base64url input or an invalid JSON.
  JwtPayloadParseError = 9,

  // Jwt signature is an invalid Base64url input.
  JwtSignatureParseError = 10,

  // Issuer is not configured.
  JwtUnknownIssuer = 11,

  // Audience is not allowed.
  JwtAudienceNotAllowed = 12,

  // Jwt verification fails.
  JwtVerificationFail = 13,

  // Jwks errors

  // Jwks is an invalid JSON.
  JwksParseError = 14,

  // Jwks does not have "keys".
  JwksNoKeys = 15,

  // "keys" in Jwks is not an array.
  JwksBadKeys = 16,

  // Jwks doesn't have any valid public key.
  JwksNoValidKeys = 17,

  // Jwks doesn't have key to match kid or alg from Jwt.
  JwksKidAlgMismatch = 18,

  // Jwks PEM public key is an invalid Base64.
  JwksPemBadBase64 = 19,

  // Jwks PEM public key parse error.
  JwksPemParseError = 19,

  // "n" or "e" field of a Jwk RSA is missing or has a parse error.
  JwksRsaParseError = 20,

  // Failed to create a EC_KEY object.
  JwksEcCreateKeyFail = 21,

  // "x" or "y" field of a Jwk EC is missing or has a parse error.
  JwksEcParseError = 22,

  // Failed to fetch public key
  JwksFetchFail = 23,

  // "kty" is missing in "keys".
  JwksMissingKty = 24,
  // "kty" is not string type in "keys".
  JwksBadKty = 25,
  // "kty" is not supported in "keys".
  JwksNotImplementedKty = 26,

  // "alg" is not started with "RS" for a RSA key
  JwksRSAKeyBadAlg = 27,
  // "n" field is missing for a RSA key
  JwksRSAKeyMissingN = 28,
  // "n" field is not string for a RSA key
  JwksRSAKeyBadN = 29,
  // "e" field is missing for a RSA key
  JwksRSAKeyMissingE = 30,
  // "e" field is not string for a RSA key
  JwksRSAKeyBadE = 31,

  // "alg" is not "ES256" for an EC key
  JwksECKeyBadAlg = 32,
  // "x" field is missing for an EC key
  JwksECKeyMissingX = 33,
  // "x" field is not string for an EC key
  JwksECKeyBadX = 34,
  // "y" field is missing for an EC key
  JwksECKeyMissingY = 35,
  // "y" field is not string for an EC key
  JwksECKeyBadY = 36,
};

/**
 * Convert enum status to string.
 * @param status is the enum status.
 * @return the string status.
 */
std::string getStatusString(Status status);

/**
 * Base class to keep the status that represents "OK" or the first failure.
 */
class WithStatus {
 public:
  WithStatus() : status_(Status::Ok) {}

  /**
   * Get the current status.
   * @return the enum status.
   */
  Status getStatus() const { return status_; }

 protected:
  void updateStatus(Status status) {
    // Only keep the first failure
    if (status_ == Status::Ok) {
      status_ = status;
    }
  }

 private:
  // The internal status.
  Status status_;
};

}  // namespace jwt_verify
}  // namespace google
