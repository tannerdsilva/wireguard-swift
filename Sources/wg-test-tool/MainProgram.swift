import ArgumentParser
import wireguard_userspace_nio
import RAW_base64
import RAW_dh25519
import RAW
import ServiceLifecycle
import Logging
import wireguard_crypto_core
import bedrock_ip
@main
struct CLI:AsyncParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wg-test-tool",
		abstract:"a development tool to aid in the development of the wireguard-userspace-nio target (and others).",
		subcommands:[
			GenerateKeys.self,
			ComputeSharedKey.self,
			TestPerformance.self,
			MessageInterface.self,
			SendData.self
		]
	)

	struct GenerateKeys:ParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Generate a new WireGuard key pair."
		)
		func run() throws {
			let (publicKey, privateKey) = try dhGenerate()
			let publicKeyBase64 = String(RAW_base64.encode(publicKey))
			let privateKeyBase64 = String(RAW_base64.encode(privateKey))
			print("Public Key: \(publicKeyBase64)")
			print("Private Key: \(privateKeyBase64)")
		}
	}

	struct ComputeSharedKey:ParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Compute a shared key from a private key and a public key."
		)

		@Argument(help: "The private key to use for the computation.")
		var privateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		@Argument(help: "The public key to use for the computation.")
		var publicKey:PublicKey

		func run() throws {
			var privKeyCopy = privateKey
			var pubKeyCopy = publicKey
			let sharedKey = try MemoryGuarded<SharedKey>.compute(privateKey:privKeyCopy, publicKey:pubKeyCopy)
			print("shared secret: \(String(RAW_base64.encode(sharedKey)))")
		}
	}
	
	actor RecTracker {
		private(set) var count = 0
		func add() { count += 1 }
		func getCount() -> Int { return count }
	}
	
	struct TestPerformance:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			abstract: "Test performance of the WireGuard client."
		)
		
		func run() async throws {
			let cliLogger = Logger(label: "wg-test-tool.initiator")

			let (myPublicKey, myPrivateKey) = try dhGenerate()
			let (peerPublicKey, peerPrivateKey) = try dhGenerate()
			let payloadSize: Int = 2_000_000
			
			var payload = [UInt8](repeating: 0, count: payloadSize)
			for i in 0..<payloadSize {
				payload[i] = UInt8(i%256)
			}
			
			let tracker = RecTracker()
			
			@Sendable func output(input: (PublicKey, [UInt8])) {
				let (key, incomingData) = input
				cliLogger.debug("Received data that is \(incomingData.count) bytes long")
				Task { await tracker.add() }
			}
			_ = try await withThrowingTaskGroup(body: { foo in
				let myPeers = [PeerInfo(publicKey: peerPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(30))]
				let myInterface = try WGInterface<[UInt8]>(staticPrivateKey:myPrivateKey, handleFunction:output, initialConfiguration:myPeers, logLevel:.info, listeningPort: 36001)

				let peerPeers = [PeerInfo(publicKey: myPublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(30))]
				let peerInterface = try WGInterface<[UInt8]>(staticPrivateKey:peerPrivateKey, handleFunction:output, initialConfiguration:peerPeers, logLevel:.info, listeningPort: 36000)

				foo.addTask {
					try await myInterface.run()
				}
				foo.addTask {
					try await peerInterface.run()
				}
				
				cliLogger.info("WireGuard interface started. Waiting for channel initialization...")
				try await myInterface.waitForChannelInit()
				
				cliLogger.info("WireGuard interface started. Waiting for channel initialization...")
				try await peerInterface.waitForChannelInit()
				
				cliLogger.info("Channel initialized. Sending handshake initiation message...")
				try await myInterface.write(publicKey: peerPublicKey, data: payload)
				
				cliLogger.info("Channel initialized. Reading data...")
				while(await tracker.count != 1) {}
				
				foo.cancelAll()
				try await foo.waitForAll()
				return
			})
		}
	}
	
	struct MessageInterface:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			abstract: "Message interface using WireGaurd."
		)
		
		@Argument(help: "The IP address of the responder.")
		var ipAddress:String
		@Argument(help: "The port number that the responder is listening on.")
		var port:Int
		@Argument(help: "The port number that the I am is listening on.")
		var myPort:Int
		@Argument(help:"The private key that the initiator will use to forge an initial handshake.")
		var myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		@Argument(help:"The public key that the responder is expected to be operating with.")
		var respondersPublicKey:PublicKey
		
		func run() async throws {
			let cliLogger = Logger(label: "wg-test-tool.initiator")
			
			@Sendable func output(input: (PublicKey, [UInt8])) {
				let (key, incomingData) = input
				// ANSI escape codes
				let green = "\u{001B}[0;32m"
				let reset = "\u{001B}[0;0m"
				// Print green text, then reset back to normal
				print("\(green)From peer \(key): \(String(decoding: incomingData, as: Unicode.UTF8.self))\(reset)")
			}
			
			_ = try await withThrowingTaskGroup(body: { foo in
				let myPeers = [PeerInfo(publicKey: respondersPublicKey, ipAddress: ipAddress, port: port, internalKeepAlive: .seconds(30))]
				let myInterface = try WGInterface<[UInt8]>(staticPrivateKey:myPrivateKey, handleFunction: output, initialConfiguration:myPeers, logLevel:.trace, listeningPort: myPort)
				
				foo.addTask {
					try await myInterface.run()
				}
				
				cliLogger.info("WireGuard interface started. Waiting for channel initialization...")
				try await myInterface.waitForChannelInit()
				
				foo.addTask {
					while true {
						if let input = readLine(strippingNewline: true) {
							let messageBytes: [UInt8] = Array(input.utf8)
							try await myInterface.write(publicKey: respondersPublicKey, data: messageBytes)
						}
					}
				}
			})
		}
	}
	
	struct SendData:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			abstract: "Message interface using WireGaurd."
		)
		
		@Argument(help: "The IP address of the responder.")
		var ipAddress:String
		@Argument(help: "The port number that the responder is listening on.")
		var port:Int
		@Argument(help: "The port number that the I am is listening on.")
		var myPort:Int
		@Argument(help:"The private key that the initiator will use to forge an initial handshake.")
		var myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		@Argument(help:"The public key that the responder is expected to be operating with.")
		var respondersPublicKey:PublicKey
		
		func run() async throws {
			let cliLogger = Logger(label: "wg-test-tool.initiator")
			
			@Sendable func output(input: (PublicKey, [UInt8])) {
				let (key, incomingData) = input
				// ANSI escape codes
				let green = "\u{001B}[0;32m"
				let reset = "\u{001B}[0;0m"
				// Print green text, then reset back to normal
				print("\(green)From peer \(key): \(incomingData.count))\(reset)")
			}
			
			_ = try await withThrowingTaskGroup(body: { foo in
				let myPeers = [PeerInfo(publicKey: respondersPublicKey, ipAddress: ipAddress, port: port, internalKeepAlive: .seconds(30))]
				let myInterface = try WGInterface<[UInt8]>(staticPrivateKey:myPrivateKey, handleFunction: output, initialConfiguration:myPeers, logLevel:.trace, listeningPort: myPort)
				
				foo.addTask {
					try await myInterface.run()
				}
				
				cliLogger.info("WireGuard interface started. Waiting for channel initialization...")
				try await myInterface.waitForChannelInit()
				
				foo.addTask {
					while true {
						if let input = readLine(strippingNewline: true), let number = Int(input) {
							var payload = [UInt8](repeating: 0, count: number)
							try await myInterface.write(publicKey: respondersPublicKey, data: payload)
							}
						else {
							print("Invalid input, not an integer.")
						}
					}
				}
			})
		}
	}
}
