// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "cryptokit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
    ],
    products: [
        .library(name: "cryptokit", type: .static, targets: ["cryptokit"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(name: "cryptokit", dependencies: [
        ], path: "Sources"),
    ]
)
