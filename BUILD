cc_library(
    name = "base64_lib",
    srcs = [
        "base64.cc",
    ],
    hdrs = [
        "base64.h",
    ],
)

cc_library(
    name = "json_lib",
    srcs = [
        "json_loader.cc",
    ],
    hdrs = [
        "json_loader.h",
        "json_object.h",
    ],
    deps = [
        "//external:fmtlib",
        "//external:rapidjson",
    ],
)

cc_library(
    name = "jwt_lib",
    srcs = [
        "jwks.cc",
        "jwt.cc",
        "status.cc",
        "status.h",
        "utils.h",
        "verifier.cc",
    ],
    hdrs = [
        "jwks.h",
        "jwt.h",
        "verifier.h",
    ],
    deps = [
        ":base64_lib",
        ":json_lib",
        "//external:abseil_strings",
        "//external:boringssl_crypto",
        "//external:libssl",
    ],
)

cc_test(
    name = "base64_test",
    srcs = [
        "base64_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":base64_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "json_test",
    srcs = [
        "json_loader_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":json_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "jwt_test",
    srcs = [
        "jwt_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "jwks_test",
    srcs = [
        "jwks_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_pem_test",
    srcs = [
        "verify_pem_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_jwk_rsa_test",
    srcs = [
        "verify_jwk_rsa_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_jwk_ec_test",
    srcs = [
        "verify_jwk_ec_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_lib",
        "//external:googletest_main",
    ],
)
