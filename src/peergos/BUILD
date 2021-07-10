load("@io_bazel_rules_gwt//gwt:gwt.bzl", "gwt_application")

gwt_application(
  name = "Peergos",
  srcs = glob(["client/*.java"]),
  resources = glob(["*.gwt.xml"]),
  modules = ["peergos.Peergos"],
  # modules = ["peergos.client.Start"],
  deps = [
    "//src/peergos/shared:shared",
    "//gwt/gwt-2.8.3:gwt-user",
    "//gwt/gwt-2.8.3:gwt-dev",
  ],
)