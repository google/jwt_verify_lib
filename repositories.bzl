load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

BORINGSSL_COMMIT = "9df0c47bc034d60d73d216cd0e090707b3fbea58"  # same as Envoy
BORINGSSL_SHA256 = "86d0614bb9e6cb4e6444b83bb1f031755eff4bbe52cd8f4cd5720bb84a7ea9f5"

def boringssl_repositories(bind=True):
    http_archive(
        name = "boringssl",
        strip_prefix = "boringssl-" + BORINGSSL_COMMIT,
        url = "https://github.com/google/boringssl/archive/" + BORINGSSL_COMMIT + ".tar.gz",
        sha256 = BORINGSSL_SHA256,
    )

    if bind:
        native.bind(
            name = "ssl",
            actual = "@boringssl//:ssl",
        )

GOOGLETEST_COMMIT = "43863938377a9ea1399c0596269e0890b5c5515a"
GOOGLETEST_SHA256 = "7c8ece456ad588c30160429498e108e2df6f42a30888b3ec0abf5d9792d9d3a0"

def googletest_repositories(bind=True):
    http_archive(
        name = "googletest_git",
        build_file = "//:googletest.BUILD",
        strip_prefix = "googletest-" + GOOGLETEST_COMMIT,
        url = "https://github.com/google/googletest/archive/" + GOOGLETEST_COMMIT + ".tar.gz",
        sha256 = GOOGLETEST_SHA256,
    )

    if bind:
        native.bind(
            name = "googletest",
            actual = "@googletest_git//:googletest",
        )

        native.bind(
            name = "googletest_main",
            actual = "@googletest_git//:googletest_main",
        )

        native.bind(
            name = "googletest_prod",
            actual = "@googletest_git//:googletest_prod",
        )

RAPIDJSON_COMMIT = "f54b0e47a08782a6131cc3d60f94d038fa6e0a51"
RAPIDJSON_SHA256 = "4a76453d36770c9628d7d175a2e9baccbfbd2169ced44f0cb72e86c5f5f2f7cd"

def rapidjson_repositories(bind=True):
    http_archive(
        name = "com_github_tencent_rapidjson",
        build_file = "//:rapidjson.BUILD",
        strip_prefix = "rapidjson-" + RAPIDJSON_COMMIT,
        url = "https://github.com/tencent/rapidjson/archive/" + RAPIDJSON_COMMIT + ".tar.gz",
        sha256 = RAPIDJSON_SHA256,
    )

    if bind:
        native.bind(
            name = "rapidjson",
            actual = "@com_github_tencent_rapidjson//:rapidjson",
        )

ABSEIL_COMMIT = "cc8dcd307b76a575d2e3e0958a4fe4c7193c2f68"  # same as Envoy
ABSEIL_SHA256 = "e35082e88b9da04f4d68094c05ba112502a5063712f3021adfa465306d238c76"

def abseil_repositories(bind=True):
    http_archive(
        name = "com_google_absl",
        strip_prefix = "abseil-cpp-" + ABSEIL_COMMIT,
        url = "https://github.com/abseil/abseil-cpp/archive/" + ABSEIL_COMMIT + ".tar.gz",
        sha256 = ABSEIL_SHA256,
    )

    if bind:
        native.bind(
            name = "abseil_strings",
            actual = "@com_google_absl//absl/strings:strings",
        )
        native.bind(
            name = "abseil_time",
            actual = "@com_google_absl//absl/time:time",
        )
    _cctz_repositories(bind)

CCTZ_COMMIT = "e19879df3a14791b7d483c359c4acd6b2a1cd96b"
CCTZ_SHA256 = "35d2c6cf7ddef1cf7c1bb054bdf2e8d7778242f6d199591a834c14d224b80c39"

def _cctz_repositories(bind=True):
    http_archive(
        name = "com_googlesource_code_cctz",
        url = "https://github.com/google/cctz/archive/" + CCTZ_COMMIT + ".tar.gz",
        sha256 = CCTZ_SHA256,
    )