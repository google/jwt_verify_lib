licenses(["notice"])

package(default_visibility = ["//visibility:public"])

exports_files(["LICENSE"])

load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

cc_fuzz_test(
    name = "fuzz_test",
    srcs = [
        "fuzz_test.cc",
    ],
    corpus = glob(["corpus/*"]),
    deps = [
        "//:jwt_verify_lib",
        "//external:abseil_strings",
    ],
)
