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
    
        static let privateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI="), count:32)!
        static let publicKey = PublicKey(privateKey: privateKey)

        // MARK: Codable – round‑trip
        @Test func encodeDecodePeer() throws {
            let original = PeerInfoNoFifo(publicKey: PeerTests.publicKey, ipAddress: "127.0.0.1", port: 8080, internalKeepAlive: .seconds(25))

            let data = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(PeerInfoNoFifo.self, from: data)

            #expect(original == decoded)
        }

        @Test func encodeDecodeRoundtripMissingEndpoint() throws {
            let original = PeerInfoNoFifo(publicKey: PeerTests.publicKey, endpoint: nil, internalKeepAlive: .seconds(10))

            let data = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(PeerInfoNoFifo.self, from: data)

            #expect(original == decoded)
            #expect(decoded.endpoint == nil)
        }

        @Test func encodeDecodeRoundtripMissingKeepAlive() throws {
            let original = PeerInfoNoFifo(publicKey: PeerTests.publicKey, endpoint: try Endpoint(SocketAddress(ipAddress: "127.0.0.1", port: 8080)), internalKeepAlive: nil)

            let data = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(PeerInfoNoFifo.self, from: data)

            #expect(original == decoded)
            #expect(decoded.internalKeepAlive == nil)
        }
    }
}
