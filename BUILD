load("@crate_index//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_clippy", "rust_library", "rust_test")
load("@vaticle_bazel_distribution//common/assemble_versioned:rules.bzl", "assemble_versioned")
load("@vaticle_bazel_distribution//github:rules.bzl", "deploy_github")
load("@rules_pkg//pkg:zip.bzl", "pkg_zip")

rust_library(
    name = "lib",
    crate_name = "oktaws",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    deps = all_crate_deps(
        normal = True,
    ),
    proc_macro_deps = all_crate_deps(
        proc_macro = True,
    ),
)

rust_binary(
    name = "oktaws",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    deps = [":lib"] + all_crate_deps(
        normal = True,
    ),
    proc_macro_deps = all_crate_deps(
        proc_macro = True,
    ),
)

rust_test(
    name = "test",
    crate = ':oktaws',
    deps = all_crate_deps(
        normal_dev = True,
    ),
    proc_macro_deps = all_crate_deps(
        proc_macro_dev = True,
    ),
)

pkg_zip(
    name = "package",
    out = "oktaws.zip",
    srcs = [":oktaws"],
)

deploy_github(
  name = "publish",
  archive = ":package",
  organisation = "jonathanmorley",
  repository = "oktaws"
)