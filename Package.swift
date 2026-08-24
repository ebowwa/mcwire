// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "mcpeer",
    targets: [
        .executableTarget(
            name: "mcpeer",
            linkerSettings: [
                .linkedFramework("MultipeerConnectivity"),
            ]
        )
    ]
)