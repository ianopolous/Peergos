java_library(
    name = "shared",
    srcs = 
        glob(["*.java"]) + 
        glob(["cbor/*.java"]) + 
        glob(["corenode/*.java"]) + 
        glob(["crypto/*.java"]) + 
        glob(["crypto/asymmetric/*.java"]) + 
        glob(["crypto/asymmetric/curve25519/*.java"]) + 
        glob(["crypto/hash/*.java"]) + 
        glob(["crypto/password/*.java"]) + 
        glob(["crypto/random/*.java"]) + 
        glob(["crypto/symmetric/*.java"]) + 
        glob(["display/*.java"]) + 
        glob(["fingerprint/*.java"]) + 
        glob(["hamt/*.java"]) + 
        glob(["inode/*.java"]) + 
        glob(["io/*.java"]) + 
        glob(["io/ipfs/*.java"]) + 
        glob(["io/ipfs/api/*.java"]) + 
        glob(["io/ipfs/cid/*.java"]) + 
        glob(["io/ipfs/multiaddr/*.java"]) + 
        glob(["io/ipfs/multibase/*.java"]) + 
        glob(["io/ipfs/multibase/binary/*.java"]) + 
        glob(["io/ipfs/multihash/*.java"]) + 
        glob(["mutable/*.java"]) + 
        glob(["social/*.java"]) + 
        glob(["storage/*.java"]) + 
        glob(["storage/controller/*.java"]) + 
        glob(["user/*.java"]) + 
        glob(["user/app/*.java"]) + 
        glob(["user/fs/*.java"]) + 
        glob(["user/fs/cryptree/*.java"]) + 
        glob(["user/fs/erasure/*.java"], exclude=["user/fs/erasure/ErrorTests.java"]) + 
        glob(["user/fs/transaction/*.java"]) + 
        glob(["util/*.java"]) + 
        glob(["zxing/*.java"]) + 
        glob(["zxing/common/*.java"]) + 
        glob(["zxing/common/detector/*.java"]) + 
        glob(["zxing/common/reedsolomon/*.java"]) + 
        glob(["zxing/qrcode/*.java"]) + 
        glob(["zxing/qrcode/decoder/*.java"]) + 
        glob(["zxing/qrcode/detector/*.java"]) + 
        glob(["zxing/qrcode/encoder/*.java"])
    ,
    visibility = ["//visibility:public"],
    deps = [
        "//gwt/gwt-2.8.3:gwt-user",
        "//gwt/gwt-2.8.3:gwt-dev",
    ],
)