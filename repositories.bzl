load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

BORINGSSL_COMMIT = "107c03cf6d364939469194396bf7a6b2572d0f9c" # 2020-03-16, same as Envoy
BORINGSSL_SHA256 = "8ae14b52b7889cf92f3b107610b12afb5011506c77f90c7b3d4a36ed7283905a"

def boringssl_repositories(bind = True):
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

def googletest_repositories(bind = True):
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

ABSEIL_COMMIT = "cc8dcd307b76a575d2e3e0958a4fe4c7193c2f68"  # same as Envoy
ABSEIL_SHA256 = "e35082e88b9da04f4d68094c05ba112502a5063712f3021adfa465306d238c76"

def abseil_repositories(bind = True):
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

def _cctz_repositories(bind = True):
    http_archive(
        name = "com_googlesource_code_cctz",
        url = "https://github.com/google/cctz/archive/" + CCTZ_COMMIT + ".tar.gz",
        sha256 = CCTZ_SHA256,
    )

BAZEL_SKYLIB_RELEASE = "0.5.0"
BAZEL_SKYLIB_SHA256 = "b5f6abe419da897b7901f90cbab08af958b97a8f3575b0d3dd062ac7ce78541f"

def _bazel_skylib_repositories():
    http_archive(
        name = "bazel_skylib",
        sha256 = BAZEL_SKYLIB_SHA256,
        strip_prefix = "bazel-skylib-" + BAZEL_SKYLIB_RELEASE,
        url = "https://github.com/bazelbuild/bazel-skylib/archive/" + BAZEL_SKYLIB_RELEASE + ".tar.gz",
    )

RULES_CC_COMMIT = "b7fe9697c0c76ab2fd431a891dbb9a6a32ed7c3e"
RULES_CC_SHA256 = "29daf0159f0cf552fcff60b49d8bcd4f08f08506d2da6e41b07058ec50cfeaec"

def _rules_cc_repositories():
    http_archive(
        name = "rules_cc",
        sha256 = RULES_CC_SHA256,
        strip_prefix = "rules_cc-" + RULES_CC_COMMIT,
        urls = ["https://github.com/bazelbuild/rules_cc/archive/" + RULES_CC_COMMIT + ".tar.gz"],
    )

RULES_JAVA_COMMIT = "981f06c3d2bd10225e85209904090eb7b5fb26bd"
RULES_JAVA_SHA256 = "f5a3e477e579231fca27bf202bb0e8fbe4fc6339d63b38ccb87c2760b533d1c3"

def _rules_java_repositories():
    http_archive(
        name = "rules_java",
        sha256 = RULES_JAVA_SHA256,
        strip_prefix = "rules_java-" + RULES_JAVA_COMMIT,
        urls = ["https://github.com/bazelbuild/rules_java/archive/" + RULES_JAVA_COMMIT + ".tar.gz"],
    )

RULES_PROTO_COMMIT = "b0cc14be5da05168b01db282fe93bdf17aa2b9f4"
RULES_PROTO_SHA256 = "88b0a90433866b44bb4450d4c30bc5738b8c4f9c9ba14e9661deb123f56a833d"

def _rules_proto_repositories():
    http_archive(
        name = "rules_proto",
        sha256 = RULES_PROTO_SHA256,
        strip_prefix = "rules_proto-" + RULES_PROTO_COMMIT,
        urls = ["https://github.com/bazelbuild/rules_proto/archive/" + RULES_PROTO_COMMIT + ".tar.gz"],
    )

ZLIB_RELEASE = "1.2.11"
ZLIB_SHA256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1"

def _zlib_repositories():
    http_archive(
        name = "zlib",
        build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
        sha256 = ZLIB_SHA256,
        strip_prefix = "zlib-" + ZLIB_RELEASE,
        urls = ["https://zlib.net/zlib-" + ZLIB_RELEASE + ".tar.gz"],
    )

PROTOBUF_RELEASE = "3.9.1"
PROTOBUF_SHA256 = "98e615d592d237f94db8bf033fba78cd404d979b0b70351a9e5aaff725398357"

def protobuf_repositories(bind = True):
    _bazel_skylib_repositories()
    _rules_cc_repositories()
    _rules_java_repositories()
    _rules_proto_repositories()
    _zlib_repositories()
    http_archive(
        name = "com_google_protobuf",
        strip_prefix = "protobuf-" + PROTOBUF_RELEASE,
        url = "https://github.com/protocolbuffers/protobuf/archive/v" + PROTOBUF_RELEASE + ".tar.gz",
        sha256 = PROTOBUF_SHA256,
    )

    if bind:
        native.bind(
            name = "protobuf",
            actual = "@com_google_protobuf//:protobuf",
        )
