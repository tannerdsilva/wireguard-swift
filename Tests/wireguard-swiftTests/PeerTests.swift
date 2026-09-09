import Testing
import NIO
import RAW_dh25519
import RAW_base64
import RAW
import Foundation
import wireguard_crypto_core
@testable import wireguard_userspace_nio

extension WireguardSwiftTests {
    @Suite struct PeerTests {
    
        static let privateKey: MemoryGuarded<PrivateKey> = {
            let bytes = try! RAW_base64.decode("8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI=")
            return bytes.withUnsafeBytes { raw in
                return MemoryGuarded<PrivateKey>(RAW_decode:raw)!
            }
        }()
        static let publicKey = PublicKey(privateKey: privateKey)
		let sharedKey:MemoryGuarded<SharedKey>
		
		init() {
			sharedKey = try! dhKeyExchange(privateKey: WireguardSwiftTests.PeerTests.privateKey, publicKey: WireguardSwiftTests.PeerTests.publicKey)
		}

        // MARK: Codable – round‑trip
        @Test func encodeDecodePeer() throws {
			let original = PeerInfo(publicKey: PeerTests.publicKey, ipAddress: "127.0.0.1", port: 8080, internalKeepAlive: .seconds(25), inboundData: nil)

            let data = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(PeerInfo.self, from: data)

			#expect(original.publicKey == decoded.publicKey)
			#expect(original.internalKeepAlive == decoded.internalKeepAlive)
        }

        @Test func encodeDecodeRoundtripMissingEndpoint() throws {
			let original = PeerInfo(publicKey: PeerTests.publicKey, endpoint: nil, internalKeepAlive: .seconds(10), inboundData: nil)

            let data = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(PeerInfo.self, from: data)

			#expect(original.publicKey == decoded.publicKey)
			#expect(original.internalKeepAlive == decoded.internalKeepAlive)
            #expect(decoded.endpoint == nil)
        }

        @Test func encodeDecodeRoundtripMissingKeepAlive() throws {
			let original = PeerInfo(publicKey: PeerTests.publicKey, endpoint: try Endpoint(SocketAddress(ipAddress: "127.0.0.1", port: 8080)), internalKeepAlive: nil, inboundData: nil)

            let data = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(PeerInfo.self, from: data)

			#expect(original.publicKey == decoded.publicKey)
			#expect(original.endpoint == decoded.endpoint)
            #expect(decoded.internalKeepAlive == nil)
        }
		
		@Test func encodeDecodeRoundtripWithsSharedKey() throws {
			let original = PeerInfo(publicKey: PeerTests.publicKey, sharedKey: sharedKey, endpoint: try Endpoint(SocketAddress(ipAddress: "127.0.0.1", port: 8080)), internalKeepAlive: nil, inboundData: nil)

			let data = try JSONEncoder().encode(original)
			let decoded = try JSONDecoder().decode(PeerInfo.self, from: data)

			#expect(original.publicKey == decoded.publicKey)
			
			#expect(String(RAW_base64.encode(original.sharedKey!)) == String(RAW_base64.encode(decoded.sharedKey!)))
		}
    }
}
