cc_library(
    name = "jwt_lib",
    srcs = [
        "jwks.cc",
        "jwt.cc",
        "status.cc",
        "status.h",
        "verify.cc",
    ],
    hdrs = [
        "jwks.h",
        "jwt.h",
        "verify.h",
    ],
    deps = [
        "//external:abseil_strings",
        "//external:rapidjson",
        "//external:ssl",
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
