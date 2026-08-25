// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "mcwire-oracle",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "mcpeer",
            linkerSettings: [
                .linkedFramework("MultipeerConnectivity"),
            ]
        ),
        .executableTarget(
            name: "mcoracle",
            linkerSettings: [
                .linkedFramework("MultipeerConnectivity"),
                .linkedFramework("AppKit"),
            ]
        ),
    ]
)