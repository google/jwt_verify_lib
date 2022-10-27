licenses(["notice"])

package(default_visibility = ["//visibility:public"])

exports_files(["LICENSE"])

load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

cc_fuzz_test(
    name = "jwt_verify_lib_fuzz_test",
    srcs = [
        "jwt_verify_lib_fuzz_test.cc",
    ],
    corpus = glob(["corpus/jwt_verify_lib_fuzz_test/*"]),
    deps = [
        "//:jwt_verify_lib",
        "//external:abseil_strings",
    ],
)
