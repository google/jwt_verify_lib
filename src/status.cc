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

#include <iostream>
#include <map>

namespace google {
namespace jwt_verify {

std::string getStatusString(Status status) {
  switch (status) {
    case Status::Ok:
      return "OK";
    case Status::JwtMissed:
      return "Jwt is missing";
    case Status::JwtNotYetValid:
      return "Jwt not yet valid";
    case Status::JwtExpired:
      return "Jwt is expired";
    case Status::JwtBadFormat:
      return "Jwt is not in the form of Header.Payload.Signature with two dots "
             "and 3 sections";
    case Status::JwtHeaderParseErrorBadBase64:
      return "Jwt header is an invalid Base64url encoded";
    case Status::JwtHeaderParseErrorBadJson:
      return "Jwt header is an invalid JSON";
    case Status::JwtHeaderBadAlg:
      return "Jwt header [alg] field is required and must be a string";
    case Status::JwtHeaderNotImplementedAlg:
      return "Jwt header [alg] is not supported";
    case Status::JwtHeaderBadKid:
      return "Jwt header [kid] field is not a string";
    case Status::JwtPayloadParseErrorBadBase64:
      return "Jwt payload is an invalid Base64url encoded";
    case Status::JwtEd25519SignatureWrongLength:
      return "Jwt ED25519 signature is wrong length";
    case Status::JwtPayloadParseErrorBadJson:
      return "Jwt payload is an invalid JSON";
    case Status::JwtPayloadParseErrorIssNotString:
      return "Jwt payload [iss] field is not a string";
    case Status::JwtPayloadParseErrorSubNotString:
      return "Jwt payload [sub] field is not a string";
    case Status::JwtPayloadParseErrorIatNotInteger:
      return "Jwt payload [iat] field is not an integer";
    case Status::JwtPayloadParseErrorNbfNotInteger:
      return "Jwt payload [nbf] field is not an integer";
    case Status::JwtPayloadParseErrorExpNotInteger:
      return "Jwt payload [exp] field is not an integer";
    case Status::JwtPayloadParseErrorJtiNotString:
      return "Jwt payload [jti] field is not a string";
    case Status::JwtPayloadParseErrorAudNotString:
      return "Jwt payload [aud] field is not a string or string list";
    case Status::JwtSignatureParseErrorBadBase64:
      return "Jwt signature is an invalid Base64url encoded";
    case Status::JwtUnknownIssuer:
      return "Jwt issuer is not configured";
    case Status::JwtAudienceNotAllowed:
      return "Audiences in Jwt are not allowed";
    case Status::JwtVerificationFail:
      return "Jwt verification fails";
    case Status::JwtMultipleTokens:
      return "Found multiple Jwt tokens";

    case Status::JwksParseError:
      return "Jwks is an invalid JSON";
    case Status::JwksNoKeys:
      return "Jwks does not have [keys] field";
    case Status::JwksBadKeys:
      return "[keys] in Jwks is not an array";
    case Status::JwksNoValidKeys:
      return "Jwks doesn't have any valid public key";
    case Status::JwksKidAlgMismatch:
      return "Jwks doesn't have key to match kid or alg from Jwt";
    case Status::JwksRsaParseError:
      return "Jwks RSA [n] or [e] field is missing or has a parse error";
    case Status::JwksEcCreateKeyFail:
      return "Jwks EC create key fail";
    case Status::JwksEcXorYBadBase64:
      return "Jwks EC [x] or [y] field is an invalid Base64.";
    case Status::JwksEcParseError:
      return "Jwks EC [x] and [y] fields have a parse error.";
    case Status::JwksOctBadBase64:
      return "Jwks Oct key is an invalid Base64";
    case Status::JwksOKPXBadBase64:
      return "Jwks OKP [x] field is an invalid Base64.";
    case Status::JwksOKPXWrongLength:
      return "Jwks OKP [x] field is wrong length.";
    case Status::JwksFetchFail:
      return "Jwks remote fetch is failed";

    case Status::JwksMissingKty:
      return "[kty] is missing in [keys]";
    case Status::JwksBadKty:
      return "[kty] is bad in [keys]";
    case Status::JwksNotImplementedKty:
      return "[kty] is not supported in [keys]";

    case Status::JwksRSAKeyBadAlg:
      return "[alg] is not started with [RS] or [PS] for an RSA key";
    case Status::JwksRSAKeyMissingN:
      return "[n] field is missing for a RSA key";
    case Status::JwksRSAKeyBadN:
      return "[n] field is not string for a RSA key";
    case Status::JwksRSAKeyMissingE:
      return "[e] field is missing for a RSA key";
    case Status::JwksRSAKeyBadE:
      return "[e] field is not string for a RSA key";

    case Status::JwksECKeyBadAlg:
      return "[alg] is not started with [ES] for an EC key";
    case Status::JwksECKeyBadCrv:
      return "[crv] field is not string for an EC key";
    case Status::JwksECKeyAlgOrCrvUnsupported:
      return "[crv] or [alg] field is not supported for an EC key";
    case Status::JwksECKeyAlgNotCompatibleWithCrv:
      return "[crv] field specified is not compatible with [alg] for an EC key";
    case Status::JwksECKeyMissingX:
      return "[x] field is missing for an EC key";
    case Status::JwksECKeyBadX:
      return "[x] field is not string for an EC key";
    case Status::JwksECKeyMissingY:
      return "[y] field is missing for an EC key";
    case Status::JwksECKeyBadY:
      return "[y] field is not string for an EC key";

    case Status::JwksHMACKeyBadAlg:
      return "[alg] does not start with [HS] for an HMAC key";
    case Status::JwksHMACKeyMissingK:
      return "[k] field is missing for an HMAC key";
    case Status::JwksHMACKeyBadK:
      return "[k] field is not string for an HMAC key";

    case Status::JwksOKPKeyBadAlg:
      return "[alg] is not [EdDSA] for an OKP key";
    case Status::JwksOKPKeyMissingCrv:
      return "[crv] field is missing for an OKP key";
    case Status::JwksOKPKeyBadCrv:
      return "[crv] field is not string for an OKP key";
    case Status::JwksOKPKeyCrvUnsupported:
      return "[crv] field is not supported for an OKP key";
    case Status::JwksOKPKeyMissingX:
      return "[x] field is missing for an OKP key";
    case Status::JwksOKPKeyBadX:
      return "[x] field is not string for an OKP key";

    case Status::JwksX509BioWriteError:
      return "X509 parse pubkey internal fails: memory allocation";
    case Status::JwksX509ParseError:
      return "X509 parse pubkey fails";
    case Status::JwksX509GetPubkeyError:
      return "X509 parse pubkey internal fails: get pubkey";

    case Status::JwksPemNotImplementedKty:
      return "PEM Key type is not supported";
    case Status::JwksPemBadBase64:
      return "PEM pubkey parse fails";
    case Status::JwksPemGetRawEd25519Error:
      return "PEM failed to get raw ED25519 key";

    case Status::JwksBioAllocError:
      return "Failed to create BIO due to memory allocation failure";
  };
  return "";
}


std::string getStatusName(Status status) {
  switch (status) {
    case Status::Ok:
      return "OK";
    case Status::JwtMissed:
      return "JWT_MISSED";
    case Status::JwtNotYetValid:
      return "JWT_NOT_YET_VALID";
    case Status::JwtExpired:
      return "JWT_EXPIRED";
    case Status::JwtBadFormat:
      return "JWT_BAD_FORMAT";
    case Status::JwtHeaderParseErrorBadBase64:
      return "JWT_HEADER_PARSE_ERROR_BAD_BASE64";
    case Status::JwtHeaderParseErrorBadJson:
      return "JWT_HEADER_PARSE_ERROR_BAD_JSON";
    case Status::JwtHeaderBadAlg:
      return "JWT_HEADER_BAD_ALG";
    case Status::JwtHeaderNotImplementedAlg:
      return "JWT_HEADER_NOT_IMPLEMENTED_ALG";
    case Status::JwtHeaderBadKid:
      return "JWT_HEADER_BAD_KID";
    case Status::JwtPayloadParseErrorBadBase64:
      return "JWT_PAYLOAD_PARSE_ERROR_BAD_BASE64";
    case Status::JwtEd25519SignatureWrongLength:
      return "JWT_ED25519_SIGNATURE_WRONG_LENGTH";
    case Status::JwtPayloadParseErrorBadJson:
      return "JWT_PAYLOAD_PARSE_ERROR_BAD_JSON";
    case Status::JwtPayloadParseErrorIssNotString:
      return "JWT_PAYLOAD_PARSE_ERROR_ISS_NOT_STRING";
    case Status::JwtPayloadParseErrorSubNotString:
      return "JWT_PAYLOAD_PARSE_ERROR_SUB_NOT_STRING";
    case Status::JwtPayloadParseErrorIatNotInteger:
      return "JWT_PAYLOAD_PARSE_ERROR_IAT_NOT_INTEGER";
    case Status::JwtPayloadParseErrorNbfNotInteger:
      return "JWT_PAYLOAD_PARSE_ERROR_NBF_NOT_INTEGER";
    case Status::JwtPayloadParseErrorExpNotInteger:
      return "JWT_PAYLOAD_PARSE_ERROR_EXP_NOT_INTEGER";
    case Status::JwtPayloadParseErrorJtiNotString:
      return "JWT_PAYLOAD_PARSE_ERROR_JTI_NOT_STRING";
    case Status::JwtPayloadParseErrorAudNotString:
      return "JWT_PAYLOAD_PARSE_ERROR_AUD_NOT_STRING";
    case Status::JwtSignatureParseErrorBadBase64:
      return "JWT_PAYLOAD_PARSE_ERROR_BAD_BASE64";
    case Status::JwtUnknownIssuer:
      return "JWT_UNKNOWN_ISSUER";
    case Status::JwtAudienceNotAllowed:
      return "JWT_AUDIENCE_NOT_ALLOWED";
    case Status::JwtVerificationFail:
      return "JWT_VERIFICATION_FAIL";
    case Status::JwtMultipleTokens:
      return "JWT_MULTIPLE_TOKENS";

    case Status::JwksParseError:
      return "JWKS_PARSE_ERROR";
    case Status::JwksNoKeys:
      return "JWKS_NO_KEYS";
    case Status::JwksBadKeys:
      return "JWKS_BAD_KEYS";
    case Status::JwksNoValidKeys:
      return "JWKS_NO_VALID_KEYS";
    case Status::JwksKidAlgMismatch:
      return "JWKS_KID_ALG_MISMATCH";
    case Status::JwksRsaParseError:
      return "JWKS_RSA_PARSE_ERROR";
    case Status::JwksEcCreateKeyFail:
      return "JWKS_EC_CREATE_KEY_FAIL";
    case Status::JwksEcXorYBadBase64:
      return "JWKS_EC_XOR_Y_BAD_BASE64";
    case Status::JwksEcParseError:
      return "JWKS_EC_PARSE_ERROR";
    case Status::JwksOctBadBase64:
      return "JJWKS_OCT_BAD_BASE64";
    case Status::JwksOKPXBadBase64:
      return "JWKS_OKP_X_BAD_BASE64";
    case Status::JwksOKPXWrongLength:
      return "JWKS_OKP_X_WRONG_LENGTH";
    case Status::JwksFetchFail:
      return "JWKS_FETCH_FAIL";

    case Status::JwksMissingKty:
      return "JWKS_MISSING_KTY";
    case Status::JwksBadKty:
      return "JWKS_BAD_KTY";
    case Status::JwksNotImplementedKty:
      return "JWKS_NOT_IMPLEMENTED_KTY";

    case Status::JwksRSAKeyBadAlg:
      return "JWKS_RSA_KEY_BAD_ALG";
    case Status::JwksRSAKeyMissingN:
      return "JWKS_RSA_KEY_MISSING_N";
    case Status::JwksRSAKeyBadN:
      return "JWKS_RSA_KEY_BAD_N";
    case Status::JwksRSAKeyMissingE:
      return "JWKS_RSA_KEY_MISSING_E";
    case Status::JwksRSAKeyBadE:
      return "JWKS_RSA_KEY_BAD_E";

    case Status::JwksECKeyBadAlg:
      return "JWKS_EC_KEY_BAD_ALG";
    case Status::JwksECKeyBadCrv:
      return "JWKS_EC_KEY_BAD_CRV";
    case Status::JwksECKeyAlgOrCrvUnsupported:
      return "JWKS_EC_KEY_ALG_OR_CRV_UNSUPPORTED";
    case Status::JwksECKeyAlgNotCompatibleWithCrv:
      return "JWKS_EC_KEY_ALG_NOT_COMPATIBLE_WITH_CRV";
    case Status::JwksECKeyMissingX:
      return "JWKS_EC_KEY_MISSING_X";
    case Status::JwksECKeyBadX:
      return "JWKS_EC_KEY_BAD_X";
    case Status::JwksECKeyMissingY:
      return "JWKS_EC_KEY_MISSING_Y";
    case Status::JwksECKeyBadY:
      return "JWKS_EC_KEY_BAD_Y";

    case Status::JwksHMACKeyBadAlg:
      return "JWKS_HMAC_KEY_BAD_ALG";
    case Status::JwksHMACKeyMissingK:
      return "JWKS_HMAC_KEY_MISSING_K";
    case Status::JwksHMACKeyBadK:
      return "JWKS_HMAC_KEY_BAD_K";

    case Status::JwksOKPKeyBadAlg:
      return "JWKS_OKP_KEY_BAD_ALG";
    case Status::JwksOKPKeyMissingCrv:
      return "JWKS_OKP_KEY_MISSING_CRV";
    case Status::JwksOKPKeyBadCrv:
      return "JWKS_OKP_KEY_BAD_CRV";
    case Status::JwksOKPKeyCrvUnsupported:
      return "JWKS_OKP_KEY_CRV_UNSUPPORTED";
    case Status::JwksOKPKeyMissingX:
      return "JWKS_OKP_KEY_MISSING_X";
    case Status::JwksOKPKeyBadX:
      return "JWKS_OKP_KEY_BAD_X";

    case Status::JwksX509BioWriteError:
      return "JWKS_X509_BIO_WRITE_ERROR";
    case Status::JwksX509ParseError:
      return "JWKS_X509_PARSE_ERROR";
    case Status::JwksX509GetPubkeyError:
      return "JWKS_X509_GET_PUBKEY_ERROR";

    case Status::JwksPemNotImplementedKty:
      return "JWKS_PEM_NOT_IMPLEMENTED_KTY";
    case Status::JwksPemBadBase64:
      return "JWKS_PEM_BAD_BASE64";
    case Status::JwksPemGetRawEd25519Error:
      return "JWKS_PEM_GET_RAW_ED_25519_ERROR";

    case Status::JwksBioAllocError:
      return "JWKS_BIO_ALLOC_ERROR";
  };
  return "";
}

}  // namespace jwt_verify
}  // namespace google
