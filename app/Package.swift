// swift-tools-version:5.9
// App de macOS de mac-cleaner (F5A). Se compila con las Command Line Tools (sin Xcode): ver empaquetar.sh.
import PackageDescription

let package = Package(
    name: "MacCleaner",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "MacCleaner", path: "Sources/MacCleaner"),
    ]
)
