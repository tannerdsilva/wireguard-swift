// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "wireguard-swift",
	platforms:[
		.macOS(.v15)
	],
	products: [
		.executable(name:"wg-test-tool", targets:["wg-test-tool"]),
		.library(name:"wireguard-userspace-nio", targets: ["wireguard-userspace-nio"]),
	],
	dependencies: [
        .package(url:"https://github.com/tannerdsilva/rawdog.git", "19.0.0"..<"20.0.0"),
		.package(url:"https://github.com/apple/swift-log.git", "1.6.3"..<"2.0.0"),
		.package(url:"https://github.com/apple/swift-nio.git", "2.84.0"..<"3.0.0"),
		.package(url:"https://github.com/tannerdsilva/bedrock.git", "6.0.1"..<"7.0.0"),
		.package(url:"https://github.com/apple/swift-argument-parser.git", "1.6.1"..<"2.0.0"),
        .package(url:"https://github.com/swift-server/swift-service-lifecycle", "2.4.0"..<"3.0.0")
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.executableTarget(
			name:"wg-test-tool",
			dependencies:[
				"wireguard-userspace-nio",
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"RAW_base64", package:"rawdog"),
				.product(name:"RAW", package:"rawdog"),
				.product(name:"ServiceLifecycle", package:"swift-service-lifecycle"),
			]
		),
		.target(
			name: "wireguard-userspace-nio",
			dependencies:[
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"RAW_chachapoly", package:"rawdog"),
				.product(name:"NIO", package:"swift-nio"),
				.product(name:"bedrock", package:"bedrock"),
                .product(name:"bedrock_fifo", package:"bedrock"),
				.product(name:"bedrock_future", package:"bedrock"),
				.product(name:"RAW_xchachapoly", package:"rawdog"),
				.product(name:"RAW_blake2", package:"rawdog"),
				.product(name:"RAW_hmac", package:"rawdog"),
                .product(name:"ServiceLifecycle", package:"swift-service-lifecycle"),
				.product(name:"bedrock_ip", package:"bedrock"),
			]
		),
		.testTarget(
			name: "wireguard-swiftTests",
			dependencies: [
				"wireguard-userspace-nio",
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"RAW_base64", package:"rawdog"),
				.product(name:"RAW", package:"rawdog")
			]
		),
	]
)
