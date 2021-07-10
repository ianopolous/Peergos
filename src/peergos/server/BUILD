SRCS = \
    glob(["*.java"]) + \
    glob(["cli/*.java"]) + \
    glob(["corenode/*.java"]) + \
    glob(["crypto/*.java"]) + \
    glob(["crypto/asymmetric/*.java"]) + \
    glob(["crypto/asymmetric/curve25519/*.java"]) + \
    glob(["crypto/hash/*.java"]) + \
    glob(["crypto/hash/lambdaworks/*.java"]) + \
    glob(["crypto/hash/lambdaworks/codec/*.java"]) + \
    glob(["crypto/hash/lambdaworks/crypto/*.java"]) + \
    glob(["crypto/hash/lambdaworks/jni/*.java"]) + \
    glob(["crypto/random/*.java"]) + \
    glob(["crypto/symmetric/*.java"]) + \
    glob(["fuse/*.java"]) + \
    glob(["messages/*.java"]) + \
    glob(["mutable/*.java"]) + \
    glob(["net/*.java"]) + \
    glob(["simulation/*.java"]) + \
    glob(["social/*.java"]) + \
    glob(["space/*.java"]) + \
    glob(["sql/*.java"]) + \
    glob(["storage/*.java"]) + \
    glob(["storage/admin/*.java"]) + \
    glob(["util/*.java"])  

java_binary(
    name = "server",
    srcs = SRCS,
    main_class = "peergos.server.Main",
    deps = [
        "//src/peergos/shared:shared",
        "//lib:lib",
    ]
)

