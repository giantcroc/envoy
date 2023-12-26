licenses(["notice"])  # Apache 2

cc_library(
    name = "crypto",
    srcs = [
        "crypto/libcrypto.a",
    ],
    hdrs = glob(["my_boringssl-32fe277f40bbed3b3ada3a1976f9e8b71157b3f4/include/openssl/*.h"]),
    defines = ["BORINGSSL_FIPS1"],
    includes = ["my_boringssl-32fe277f40bbed3b3ada3a1976f9e8b71157b3f4/include"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    srcs = [
        "ssl/libssl.a",
    ],
    hdrs = glob(["my_boringssl-32fe277f40bbed3b3ada3a1976f9e8b71157b3f4/include/openssl/*.h"]),
    includes = ["my_boringssl-32fe277f40bbed3b3ada3a1976f9e8b71157b3f4/include"],
    visibility = ["//visibility:public"],
    deps = [":crypto"],
)

genrule(
    name = "build",
    srcs = glob(["my_boringssl-32fe277f40bbed3b3ada3a1976f9e8b71157b3f4/**"]),
    outs = [
        "crypto/libcrypto.a",
        "ssl/libssl.a",
    ],
    cmd = "$(location {}) $(location crypto/libcrypto.a) $(location ssl/libssl.a)".format("@envoy//bazel/external:boringssl_fips.genrule_cmd"),
    tools = ["@envoy//bazel/external:boringssl_fips.genrule_cmd"],
)
