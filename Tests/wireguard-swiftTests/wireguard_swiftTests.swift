import Testing
import Foundation
@testable import wireguard_userspace_nio
import RAW_dh25519
import RAW_base64
import RAW_xchachapoly
import RAW
import NIO
import Logging
import ServiceLifecycle
import wireguard_crypto_core

@Suite("WG Swift Tests", .serialized)
struct WireguardSwiftTests {}

extension WireguardSwiftTests {
	@Suite("WG Crypto Tests",
		.serialized
	)
	struct CryptoTests {
		@Test func testCreateInitilizationMessage() throws {
			let staticPublicKey = try dhGenerate()
			let peerPublicKey = try dhGenerate().0
			
			let (_, _, _, payload) = try withUnsafePointer(to: peerPublicKey) { q in
				return try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:staticPublicKey.1, responderStaticPublicKey: q)
			}

			let _ = try withUnsafePointer(to: staticPublicKey) { p in
				try withUnsafePointer(to: peerPublicKey) { q in
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
			var initiatorPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			var initiatorPublicKey = PublicKey(privateKey:initiatorPrivateKey)
			var responderStaticPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			var responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
			var constructedPacket = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:initiatorPrivateKey, responderStaticPublicKey: &responderStaticPublicKey)
			var authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey)
			let responderValidationStep = try authenticatedPacketToSend.validate(responderStaticPrivateKey:responderStaticPrivateKey)
		}

		@Test func selfValidateResponse() throws {
			var initiatorPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			var initiatorPublicKey = PublicKey(privateKey:initiatorPrivateKey)
			var initiatorEphemeralPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			var initiatorEphemeralPublicKey = PublicKey(privateKey:initiatorEphemeralPrivateKey)
			var sharedKey = Result.Bytes32(RAW_staticbuff:Result.Bytes32.RAW_staticbuff_zeroed()) // 0^32 shared key default
			var senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
			var constructedPacket = try Message.Response.Payload.forge(c: sharedKey, h: sharedKey, initiatorPeerIndex: senderIndex, initiatorStaticPublicKey: &initiatorPublicKey, initiatorEphemeralPublicKey: initiatorEphemeralPublicKey, preSharedKey: sharedKey)
			var authenticatedPacket = try constructedPacket.payload.finalize(initiatorStaticPublicKey: &initiatorPublicKey)
			let responseValidationStep = try authenticatedPacket.validate(c:sharedKey, h:sharedKey, initiatorStaticPrivateKey:initiatorPrivateKey, initiatorEphemeralPrivateKey:initiatorEphemeralPrivateKey, preSharedKey: sharedKey)
		}

		@Test func selfValidateDataPacket() throws {
			try Result.Bytes32(RAW_staticbuff: try generateRandomBytes(count: 32)).RAW_access_staticbuff { cPtr in
				let (TIsend, _) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key: cPtr, count:MemoryLayout<Result.Bytes32>.size, data: [] as [UInt8], count:0)
				let (TRrecv, _) = try wgKDFv2((Result.Bytes32, Result.Bytes32).self, key: cPtr, count:MemoryLayout<Result.Bytes32>.size, data: [] as [UInt8], count:0)

				let senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
				
				let message:String = "This is a message to be encrypted"
				let messageBytes: [UInt8] = Array(message.utf8)
				var nonce_i:Counter = Counter(RAW_native: 0)
				
				var encryptedPacket = try Message.Data.Payload.forge(receiverIndex: senderIndex, nonce: &nonce_i, transportKey: TIsend, plainText: messageBytes)
				
				var nonce_r:Counter = Counter(RAW_native: 0)

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
			var initiatorPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			
			var initiatorPublicKey = PublicKey(privateKey:initiatorPrivateKey)
			
			var responderStaticPrivateKey = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
			
			var responderStaticPublicKey = PublicKey(privateKey:responderStaticPrivateKey)
			
			// Pre-computing HASH(LABEL-COOKIE || Spub)
			var hasher = try! WGHasherV2<RAW_xchachapoly.Key>()
			try! hasher.update([UInt8]("cookie--".utf8))
			try! hasher.update(responderStaticPublicKey)
			let precomputedCookieKey = try! hasher.finish()
			
			var constructedPacket = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:initiatorPrivateKey, responderStaticPublicKey:&responderStaticPublicKey)
			var authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey)
			let endpoint = try SocketAddress(ipAddress: "192.0.2.1", port: 51820)
			let secretCookieR = try! generateSecureRandomBytes(as:Result.Bytes8.self)
			let cookie = try Message.Cookie.Payload.forgeNoNIO(receiverPeerIndex: authenticatedPacketToSend.payload.initiatorPeerIndex, k: precomputedCookieKey, r: secretCookieR, endpoint:Endpoint(endpoint), m: authenticatedPacketToSend.msgMac1)

			authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey, cookie: cookie)

			try authenticatedPacketToSend.validateUnderLoadNoNIO(responderStaticPrivateKey:responderStaticPrivateKey, R: secretCookieR, endpoint:Endpoint(endpoint))
		}
	}
}

extension WireguardSwiftTests {
	@Suite("Live Socket Tests",
		.serialized
	)
	struct LiveSocketTests {
		
		let myPublicKey: PublicKey
		let myPrivateKey: MemoryGuarded<PrivateKey>
		
		let peerPublicKey: PublicKey
		let peerPrivateKey: MemoryGuarded<PrivateKey>

		let cliLogger = Logger(label: "wg-test-tool.initiator")
		
		init() throws {
			(myPublicKey, myPrivateKey) = try dhGenerate()
			(peerPublicKey, peerPrivateKey) = try dhGenerate()
		}
		
		@Test func sendSingleString() async throws {
			let stringToSend = "Hello, world!"
			let messageBytes: [UInt8] = Array(stringToSend.utf8)
			
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
				try await myInterface.write(publicKey: peerPublicKey, data: messageBytes)
				
				cliLogger.info("Channel initialized. Reading data...")
				for try await (key, incomingData) in peerInterface {
					#expect(key == myPublicKey)
					#expect(incomingData == messageBytes)
					foo.cancelAll()
					try await foo.waitForAll()
					return
				}
			})
		}

		@Test func sendMultipleSmallMessages() async throws {
			let payloadSize: Int = 10_000
			
			var payload = [UInt8](repeating: 0, count: payloadSize)
			for i in 0..<payloadSize {
				payload[i] = UInt8(i%256)
			}
			var payload2 = [UInt8](repeating: 0, count: payloadSize)
			for i in 0..<payloadSize {
				payload2[i] = UInt8(i%256)
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
				
				cliLogger.info("Sending second data packet...")
				try await myInterface.write(publicKey: peerPublicKey, data: payload2)
				
				cliLogger.info("Channel initialized. Reading data...")
				var count = 0
				for try await (key, incomingData) in peerInterface {
					if(count == 0) {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(key == myPublicKey)
						#expect(incomingData == payload)
						count += 1
					} else {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(key == myPublicKey)
						#expect(incomingData == payload2)
						foo.cancelAll()
					}
				}
			})
		}
        
        @Test func sendManySmallMessages() async throws {
            let payloadSize: Int = 2_000
            
            var payloads:[[UInt8]] = []
            for _ in 0..<1000 {
                var payload = [UInt8](repeating: 0, count: payloadSize)
                for i in 0..<payloadSize {
                    payload[i] = UInt8(i%256)
                }
                payloads.append(payload)
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
                for payload in payloads {
                    try await myInterface.write(publicKey: peerPublicKey, data: payload)
                }
                
                cliLogger.info("Channel initialized. Reading data...")
                var count = 0
                for try await (key, incomingData) in peerInterface {
                    cliLogger.debug("Received data that is \(incomingData.count) bytes long")
                    #expect(key == myPublicKey)
                    #expect(incomingData == payloads[count])
                    count += 1
                    if(count == 999) {
                        foo.cancelAll()
                    }
                }
            })
        }

		@Test func sendSingleLargeMessage() async throws {
			let payloadSize: Int = 2_000_000
			
			var payload = [UInt8](repeating: 0, count: payloadSize)
			
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
					#expect(key == myPublicKey)
					#expect(incomingData == payload)
					foo.cancelAll()
				}
			})
		}
		
		@Test func sendMultipleLargeMessages() async throws {
			let payloadSize: Int = 2_000_000
			
			var payload = [UInt8](repeating: 0, count: payloadSize)
			for i in 0..<payloadSize {
				payload[i] = UInt8(i%256)
			}
			var payload2 = [UInt8](repeating: 0, count: payloadSize)
			for i in 0..<payloadSize {
				payload2[i] = UInt8((i+5)%256)
			}
			
			_ = try await withThrowingTaskGroup(of:Void.self, returning:Void.self) { foo in
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
				
				cliLogger.info("Sending second data packet...")
				try await myInterface.write(publicKey: peerPublicKey, data: payload2)
				
				cliLogger.info("Channel initialized. Reading data...")
				var count = 0
				for try await (key, incomingData) in peerInterface {
					if(count == 0) {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(key == myPublicKey)
						#expect(incomingData == payload)
						count += 1
					} else {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(key == myPublicKey)
						#expect(incomingData == payload2)
						foo.cancelAll()
					}
				}
			}
		}
	}
	}
