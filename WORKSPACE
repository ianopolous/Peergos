load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
  name = "io_bazel_rules_gwt",
  url = "https://github.com/bazelbuild/rules_gwt/archive/0.1.3.tar.gz",
  sha256 = "3f017bd2f7734e259535da0bcc75398b883dda6da6b657dfa84bd02fab0a6916",
  strip_prefix = "rules_gwt-0.1.3",
)

# From https://github.com/bazelbuild/rules_gwt
# If you want to use a different version of GWT or any of its dependencies, you must provide your own bindings. Remove the gwt_repositories() line above and add a bind rule for each of the following in your WORKSPACE:
load("@io_bazel_rules_gwt//gwt:gwt.bzl", "gwt_repositories")
gwt_repositories()

# @domanski my hope is that this is suffcient? 
# If I remove the line above, it requests all 
# 27 `//external:gwt-*` targets to be bound below...
bind(
    name = "gwt-user",
    actual = "//gwt/gwt-2.8.3:gwt-user",
)

bind(
    name = "gwt-dev",
    actual = "//gwt/gwt-2.8.3:gwt-dev",
)