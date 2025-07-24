import ArgumentParser
import wireguard_userspace_nio
import RAW_base64
import RAW_dh25519
import RAW

@main
struct CLI:ParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wg-test-tool",
		abstract:"a development tool to aid in the development of the wireguard-userspace-nio target (and others).",
		subcommands:[
			GenerateKeys.self,
			ComputeSharedKey.self,
            Initiator.self,
            Responder.self
		]
	)

	struct GenerateKeys:ParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Generate a new WireGuard key pair."
		)

		func run() throws {
			let (publicKey, privateKey) = try dhGenerate()
			let publicKeyBase64 = String(try RAW_base64.encode(publicKey))
			let privateKeyBase64 = String(try RAW_base64.encode(privateKey))
			print("Public Key: \(publicKeyBase64)")
			print("Private Key: \(privateKeyBase64)")
		}
	}

	struct ComputeSharedKey:ParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Compute a shared key from a private key and a public key."
		)

		@Argument(help: "The private key to use for the computation.")
		var privateKey:PrivateKey
		@Argument(help: "The public key to use for the computation.")
		var publicKey:PublicKey

		func run() throws {
			var privKeyCopy = privateKey
			var pubKeyCopy = publicKey
			let sharedKey = SharedKey.compute(privateKey: &privKeyCopy, publicKey: &pubKeyCopy)
			print("shared secret: \(String(try RAW_base64.encode(sharedKey)))")
		}
	}

    struct Initiator:ParsableCommand {
        static let configuration = CommandConfiguration(
            subcommands: []
        )

		@Argument(help: "The IP address of the responder.")
		var ipAddress:String
		@Argument(help: "The port number that the responder is listening on.")
		var port:Int
		@Argument(help:"The private key that the initiator will use to forge an initial handshake.")
		var myPrivateKey:PrivateKey
		@Argument(help:"The public key that the responder is expected to be operating with.")
		var respondersPublicKey:PublicKey

		func run() throws {
			let interface = try WGInterface(ipAddress: ipAddress, port: port, staticPrivateKey: myPrivateKey, peerPublicKey: respondersPublicKey)
			try interface.sendInitialPacket()
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
}

// Create client and server struct with subcommands
