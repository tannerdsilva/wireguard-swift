import ArgumentParser
import wireguard_userspace_nio
import RAW_base64
import RAW_dh25519
import RAW
import ServiceLifecycle
import Logging
import wireguard_crypto_core
@main
struct CLI:AsyncParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wg-test-tool",
		abstract:"a development tool to aid in the development of the wireguard-userspace-nio target (and others).",
		subcommands:[
			GenerateKeys.self,
			ComputeSharedKey.self,
            Initiator.self,
            Responder.self,
			TestPerformance.self
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

    struct Initiator:AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            subcommands: []
        )

		@Argument(help: "The IP address of the responder.")
		var ipAddress:String
		@Argument(help: "The port number that the responder is listening on.")
		var port:Int
		@Argument(help:"The private key that the initiator will use to forge an initial handshake.")
		var myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		@Argument(help:"The public key that the responder is expected to be operating with.")
		var respondersPublicKey:PublicKey

		func run() async throws {
			var cliLogger = Logger(label: "wg-test-tool.initiator")
			cliLogger.logLevel = .trace
            let peers = [Peer(publicKey: respondersPublicKey, ipAddress: ipAddress, port: port, internalKeepAlive: .seconds(15))]
			let interface = try WGInterface<[UInt8]>(staticPrivateKey:myPrivateKey, initialConfiguration:peers, logLevel:.trace)
			Task {
				cliLogger.info("WireGuard interface started. Waiting for channel initialization...")
				try await interface.waitForChannelInit()
				cliLogger.info("Channel initialized. Sending handshake initiation message...")
				try await interface.write(publicKey: respondersPublicKey, data: [])
			}

			let sg = ServiceGroupConfiguration(services:[interface], gracefulShutdownSignals:[.sigint],logger: cliLogger)
			let lifecycle = ServiceGroup(configuration:sg)
			try await lifecycle.run()
		}
    }
    
    struct Responder:ParsableCommand {
        static let configuration = CommandConfiguration(
            subcommands: [
                Listen.self
            ]
        )
        
        struct Listen:ParsableCommand {
            static let configuration = CommandConfiguration(
				abstract: "Start the WireGuard client."
			)

            func run() throws {
                print("Starting WireGuard...")
                
            }
        }
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
			
			_ = try await withThrowingTaskGroup(body: { foo in
				let myPeers = [PeerInfo(publicKey: peerPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(30))]
				let myInterface = try WGInterface<[UInt8]>(staticPrivateKey:myPrivateKey, initialConfiguration:myPeers, logLevel:.trace, listeningPort: 36001)
				
				let peerPeers = [PeerInfo(publicKey: myPublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(30))]
				let peerInterface = try WGInterface<[UInt8]>(staticPrivateKey:peerPrivateKey, initialConfiguration:peerPeers, logLevel:.trace, listeningPort: 36000)

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
				for try await (key, incomingData) in peerInterface {
					cliLogger.debug("Received data that is \(incomingData.count) bytes long")
					foo.cancelAll()
				}
			})
		}
	}
}

// Create client and server struct with subcommands
