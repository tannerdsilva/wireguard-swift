@testable import wireguard_crypto_core
import Testing
import RAW_dh25519
import RAW
import RAW_base64
import NIO
import RAW_xchachapoly

extension WireguardSwiftTests {
	@Suite("WG Crypto Tests",
		.serialized
	)
	struct CryptoTests {
		@Test func testCreateInitilizationMessage() throws {
			let staticPublicKey = try dhGenerate()
			let bobPublicKey = try dhGenerate().0
			
			let (_, _, _, payload) = try withUnsafePointer(to: bobPublicKey) { q in
				return try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:staticPublicKey.1, responderStaticPublicKey: q)
			}

			let _ = try withUnsafePointer(to: staticPublicKey) { p in
				try withUnsafePointer(to: bobPublicKey) { q in
					return try payload.finalize(responderStaticPublicKey: q)
				}
			}
		}

		@Test func countedNonceSortTest() throws {
			let nonce1 = CountedNonce(integerLiteral:1)
			let nonce2 = CountedNonce(integerLiteral:2)
			let nonce3 = nonce2 + 1
			
			#expect(nonce1 < nonce2)
			#expect(nonce2 < nonce3)
			#expect(nonce3 > nonce1)
		}

		@Test func selfValidateInitiation() throws {
			let initiatorPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			let responderStaticPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			var responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
			let constructedPacket = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
			let authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey)
			_ = try authenticatedPacketToSend.validate(responderStaticPrivateKey:responderStaticPrivateKey)
		}

		@Test func selfValidateResponse() throws {
			let initiatorPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			var initiatorPublicKey = PublicKey(privateKey:initiatorPrivateKey)
			let initiatorEphemeralPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			let initiatorEphemeralPublicKey = PublicKey(privateKey:initiatorEphemeralPrivateKey)
			let zeros = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed())
			let sharedKey = try MemoryGuarded<SharedKey>.blank() // 0^32 shared key default
			let senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
			let constructedPacket = try Message.Response.Payload.forge(c: zeros, h: zeros, initiatorPeerIndex: senderIndex, initiatorStaticPublicKey: &initiatorPublicKey, initiatorEphemeralPublicKey: initiatorEphemeralPublicKey, preSharedKey: sharedKey)
			let authenticatedPacket = try constructedPacket.payload.finalize(initiatorStaticPublicKey: &initiatorPublicKey)
			_ = try authenticatedPacket.validate(c:zeros, h:zeros, initiatorStaticPrivateKey:initiatorPrivateKey, initiatorEphemeralPrivateKey:initiatorEphemeralPrivateKey, preSharedKey: sharedKey)
		}

		@Test func selfValidateDataPacket() throws {
			try Result.Bytes32(RAW_staticbuff: try generateRandomBytes(count: 32)).RAW_access_staticbuff { cPtr in
				let (TIsend, _) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key: cPtr, count:MemoryLayout<Result.Bytes32>.size, data: [] as [UInt8], count:0)
				let (TRrecv, _) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key: cPtr, count:MemoryLayout<Result.Bytes32>.size, data: [] as [UInt8], count:0)

				let senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
				
				let message:String = "This is a message to be encrypted"
				let messageBytes: [UInt8] = Array(message.utf8)
				var nonce_i:Counter = Counter(RAW_native: 0)
				
				let encryptedPacket = try Message.Data.Payload.forge(receiverIndex: senderIndex, nonce: &nonce_i, transportKey: TIsend, plainText: messageBytes)
				
				var _:Counter = Counter(RAW_native: 0)

				let decryptedPacket = try encryptedPacket.decrypt(transportKey: TRrecv)
				if let recoveredMessage = String(bytes: decryptedPacket, encoding: .utf8) {
					print("Recovered message: '\(recoveredMessage) @ \(recoveredMessage.count) bytes'")
					print("Original message: '\(message)' @ \(message.count) bytes'")
					#expect(recoveredMessage.prefix(8) == message.prefix(8))
				} else {
					struct InvalidUTF8Error:Swift.Error {}
					throw InvalidUTF8Error()
				}
			}
		}

		@Test func selfValidateCookiePacket() throws {
			let initiatorPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			
			_ = PublicKey(privateKey:initiatorPrivateKey)
			
			let responderStaticPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			
			var responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
			
			// Pre-computing HASH(LABEL-COOKIE || Spub)
			var hasher = try! WGHasher<RAW_xchachapoly.Key>()
			try! hasher.update([UInt8]("cookie--".utf8))
			try! hasher.update(responderStaticPublicKey)
			let precomputedCookieKey = try! hasher.finish()
			
			let constructedPacket = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:initiatorPrivateKey, responderStaticPublicKey:&responderStaticPublicKey)
			var authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey)
			let endpoint = try SocketAddress(ipAddress: "192.0.2.1", port: 51820)
			let secretCookieR = try! generateSecureRandomBytes(as:Result.Bytes8.self)
			let cookie = try Message.Cookie.Payload.forge(initiatorsPeerIndex: authenticatedPacketToSend.payload.initiatorPeerIndex, k: precomputedCookieKey, r: secretCookieR, endpoint:Endpoint(endpoint), m: authenticatedPacketToSend.msgMac1)

			authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey, cookie: cookie, savedMac1:authenticatedPacketToSend.msgMac1)

			try authenticatedPacketToSend.validateUnderLoad(responderStaticPrivateKey:responderStaticPrivateKey, R: secretCookieR, endpoint:Endpoint(endpoint))
		}
	}
}
