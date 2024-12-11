// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KeychainSimple",
    products: [
        .library(
            name: "KeychainSimple",
            targets: ["KeychainSimple"]),
    ],
    targets: [
        .target(
            name: "KeychainSimple"),
        .testTarget(
            name: "KeychainSimpleTests",
            dependencies: ["KeychainSimple"]
        ),
    ]
)
