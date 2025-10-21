import Testing
import Foundation
import RAW_dh25519
import RAW_base64
import RAW_chachapoly
import RAW_xchachapoly
import RAW
import NIO
import Logging
import ServiceLifecycle
import wireguard_crypto_core
import bedrock_fifo
@testable import wireguard_userspace_nio

@Suite("WG Swift Tests", .serialized)
struct WireguardSwiftTests {}

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
			var hasher = try! WGHasher<RAW_xchachapoly.Key>()
			try! hasher.update([UInt8]("cookie--".utf8))
			try! hasher.update(responderStaticPublicKey)
			let precomputedCookieKey = try! hasher.finish()
			
			var constructedPacket = try Message.Initiation.Payload.forge(initiatorStaticPrivateKey:initiatorPrivateKey, responderStaticPublicKey:&responderStaticPublicKey)
			var authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey)
			let endpoint = try SocketAddress(ipAddress: "192.0.2.1", port: 51820)
			let secretCookieR = try! generateSecureRandomBytes(as:Result.Bytes8.self)
			let cookie = try Message.Cookie.Payload.forge(receiverPeerIndex: authenticatedPacketToSend.payload.initiatorPeerIndex, k: precomputedCookieKey, r: secretCookieR, endpoint:Endpoint(endpoint), m: authenticatedPacketToSend.msgMac1)

			authenticatedPacketToSend = try constructedPacket.payload.finalize(responderStaticPublicKey: &responderStaticPublicKey, cookie: cookie)

			try authenticatedPacketToSend.validateUnderLoad(responderStaticPrivateKey:responderStaticPrivateKey, R: secretCookieR, endpoint:Endpoint(endpoint))
		}
	}
}

extension WireguardSwiftTests {
	@Suite("Live Socket Tests",
		.serialized
	)
	struct LiveSocketTests {

		static let aliceStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI="), count:32)!
		static let bobStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("SD/y8yQa/DgiYRnDI9vJEiGezNn4yLd/4yL9OLnej0A="), count:32)!
		static let carolStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("EEug1Qbe4WjR1TDq4iN4Ce4Rh5iN4aDR407/e5bQgW4="), count:32)!

		let alicePublicKey:PublicKey
		let alicePrivateKey:MemoryGuarded<PrivateKey>
		
		let bobPublicKey:PublicKey
		let bobPrivateKey:MemoryGuarded<PrivateKey>
		
		let carolPublicKey:PublicKey
		let carolPrivateKey:MemoryGuarded<PrivateKey>

		let cliLogger:Logger

		init() throws {
			(alicePublicKey, alicePrivateKey) = (PublicKey(privateKey:Self.aliceStaticPrivateKey), Self.aliceStaticPrivateKey)
			(bobPublicKey, bobPrivateKey) = (PublicKey(privateKey:Self.bobStaticPrivateKey), Self.bobStaticPrivateKey)
			(carolPublicKey, carolPrivateKey) = (PublicKey(privateKey:Self.carolStaticPrivateKey), Self.carolStaticPrivateKey)
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = .info
			cliLogger = buildLogger
		}
		
		@Test func sendSingleString() async throws {
			let stringToSend = "Hello, world!"
			let messageBytes: [UInt8] = Array(stringToSend.utf8)
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(20)), FIFO<[UInt8], Swift.Error>())]
				let aliceInterface = try WGInterface<[UInt8]>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36001)

				let aliceFifo = FIFO<[UInt8], Swift.Error>()
				let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(20)), aliceFifo)]
				let bobInterface = try WGInterface<[UInt8]>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36000)

				foo.addTask {
					try await aliceInterface.run()
				}
				foo.addTask {
					try await bobInterface.run()
				}
				
				cliLogger.info("waiting for alice's interface to initialize...")
				try await aliceInterface.waitForChannelInit()
				
				cliLogger.info("waiting for bob's interface to initialize...")
				try await bobInterface.waitForChannelInit()
				
				cliLogger.info("alice is writing...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: messageBytes)
				
				
				let iterator = aliceFifo.makeAsyncConsumer()
				while(true) {
					if let incomingData = try await iterator.next() {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == messageBytes)
						cliLogger.info("bob received data that is \(incomingData.count) bytes long")
						foo.cancelAll()
						try await foo.waitForAll()
						return
					}
				}
			})
		}

		@Test func attemptMTUOverflow() async throws {
			let stringToSend = [UInt8](repeating: 65, count: 2000)
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(20)), FIFO<[UInt8], Swift.Error>())]
				let aliceInterface = try WGInterface<[UInt8]>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36001)

				let aliceFifo = FIFO<[UInt8], Swift.Error>()
				let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(20)), aliceFifo)]
				let bobInterface = try WGInterface<[UInt8]>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36000)

				foo.addTask {
					try await aliceInterface.run()
				}
				foo.addTask {
					try await bobInterface.run()
				}
				
				cliLogger.info("waiting for alice's interface to initialize...")
				try await aliceInterface.waitForChannelInit()
				
				cliLogger.info("waiting for bob's interface to initialize...")
				try await bobInterface.waitForChannelInit()

//				try await confirmation("confirm that alice cannot successfully send a message larger than the mtu", expectedCount:0) { freeConfirm in
//					cliLogger.info("alice is writing...")
//					do {
//						try await aliceInterface.write(publicKey: bobPublicKey, data: stringToSend)
//						freeConfirm.confirm(count:1)
//					} catch let error as ChannelErrors.OutboundMessageMTUExceeded {
//						cliLogger.info("alice encountered an error sending the oversized packet, so bob should not receive anything.")
//						#expect(ChannelErrors.OutboundMessageMTUExceeded(attemptedOutboundSize:2000 + 32, mtuLimitOutbound:1400) == error)
//						foo.cancelAll()
//						try await foo.waitForAll()
//						return
//					}
//				}
				foo.cancelAll()
				try await foo.waitForAll()
				return
			})
		}

		@Test func sendSmallStringSerialized() async throws {
			let stringToSend = "Hello world!"
			let messageBytes: [UInt8] = Array(stringToSend.utf8)
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(20)), FIFO<[UInt8], Swift.Error>())]
				let aliceInterface = try WGInterface<[UInt8]>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36001)

				let aliceFifo = FIFO<[UInt8], Swift.Error>()
				let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(20)), aliceFifo)]
				let bobInterface = try WGInterface<[UInt8]>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36000)

				foo.addTask {
					try await aliceInterface.run()
				}
				foo.addTask {
					try await bobInterface.run()
				}
				
				cliLogger.info("waiting for alice's interface to initialize...")
				try await aliceInterface.waitForChannelInit()
				
				cliLogger.info("waiting for bob's interface to initialize...")
				try await bobInterface.waitForChannelInit()
				foo.addTask {
					for i in 0..<512 {
						cliLogger.trace("alice is writing a message...")
						try! await aliceInterface.write(publicKey: bobPublicKey, data: messageBytes)
					}
				}

				var found = 0
				let iterator = aliceFifo.makeAsyncConsumer()
				while(true) {
					if let incomingData = try await iterator.next() {
						#expect(incomingData == messageBytes)
						found += 1
						cliLogger.info("bob received message from alice.", metadata:["message_count":"\(found)"])
						if found == 512 {
							foo.cancelAll()
							try await foo.waitForAll()
							return
						}
					}
				}
			})
		}
		
		@Test func sendMultipleSmallMessages() async throws {
			let payloadSize: Int = 2000
			
			var tempPayload = [UInt8](repeating: 0, count: payloadSize)
			for i in 0..<payloadSize {
				tempPayload[i] = UInt8(i%256)
			}
			let payload1 = tempPayload
			let payload2 = tempPayload
			
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(20)), FIFO<[UInt8], Swift.Error>())]
				let aliceInterface = try WGInterface<[UInt8]>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36001)

				let aliceFifo = FIFO<[UInt8], Swift.Error>()
				let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(20)), aliceFifo)]
				let bobInterface = try WGInterface<[UInt8]>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36000)

				foo.addTask {
					try await aliceInterface.run()
				}
				foo.addTask {
					try await bobInterface.run()
				}
				
				cliLogger.info("waiting for alice's interface to initialize...")
				try await aliceInterface.waitForChannelInit()
				
				cliLogger.info("waiting for bob's interface to initialize...")
				try await bobInterface.waitForChannelInit()
				
				cliLogger.info("alice is sending the first data payload...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: payload1)
				
				cliLogger.info("alice is sending the second data payload...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: payload2)
				
				cliLogger.info("invoking read loop on primary task...")
				var count = 0
				let iterator = aliceFifo.makeAsyncConsumer()
				while(true) {
					if let incomingData = try await iterator.next() {
						if (count == 0) {
							cliLogger.debug("Received data that is \(incomingData.count) bytes long")
							#expect(incomingData == payload1)
							count += 1
						} else {
							cliLogger.debug("received data that is \(incomingData.count) bytes long")
							#expect(incomingData == payload2)
							foo.cancelAll()
							try await foo.waitForAll()
							return
						}
					}
				}
			})
		}
		
		@Test func sendManySmallMessages() async throws {
			let payloadSize: Int = 2_000
			var payload = [UInt8](repeating: 0, count: payloadSize)
			for i in 0..<payloadSize {
				payload[i] = UInt8(i%256)
			}
			
			let payloadCount = 1_000
			var payloads:[[UInt8]] = []
			for _ in 0..<payloadCount {
				payloads.append(payload)
			}
			
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(20)), FIFO<[UInt8], Swift.Error>())]
				let aliceInterface = try WGInterface<[UInt8]>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36001)

				let aliceFifo = FIFO<[UInt8], Swift.Error>()
				let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(20)), aliceFifo)]
				let bobInterface = try WGInterface<[UInt8]>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36000)

				foo.addTask {
					try await aliceInterface.run()
				}
				foo.addTask {
					try await bobInterface.run()
				}
				
				cliLogger.info("waiting for alice's interface to initialize...")
				try await aliceInterface.waitForChannelInit()
				
				cliLogger.info("waiting for bob's interface to initialize...")
				try await bobInterface.waitForChannelInit()
				
				cliLogger.info("Channel initialized. Sending handshake initiation message...")
				for payload in payloads {
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				}
				
				cliLogger.info("Channel initialized. Reading data...")
				var count = 0
				let iterator = aliceFifo.makeAsyncConsumer()
				while(true) {
					if let incomingData = try await iterator.next() {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == payloads[count])
						count += 1
						if (count == payloadCount - 1) {
							foo.cancelAll()
							try await foo.waitForAll()
							return
						}
					}
				}
			})
		}

		@Test func sendSingleLargeMessage() async throws {
			let payloadSize: Int = 20_000_000
			
			var payload = [UInt8](repeating: 0, count: payloadSize)
			
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(20)), FIFO<[UInt8], Swift.Error>())]
				let aliceInterface = try WGInterface<[UInt8]>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36001)

				let aliceFifo = FIFO<[UInt8], Swift.Error>()
				let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(20)), aliceFifo)]
				let bobInterface = try WGInterface<[UInt8]>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36000)

				foo.addTask {
					try await aliceInterface.run()
				}
				foo.addTask {
					try await bobInterface.run()
				}
				
				cliLogger.info("waiting for alice's interface to initialize...")
				try await aliceInterface.waitForChannelInit()
				
				cliLogger.info("waiting for bob's interface to initialize...")
				try await bobInterface.waitForChannelInit()
				
				cliLogger.info("Channel initialized. Sending handshake initiation message...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				
				cliLogger.info("Channel initialized. Reading data...")
				let iterator = aliceFifo.makeAsyncConsumer()
				while(true) {
					if let incomingData = try await iterator.next() {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == payload)
						foo.cancelAll()
						try await foo.waitForAll()
						return
					}
				}
			})
		}
				
		
		@Test func sendFromMultiplePeers() async throws {
			let payloadSize: Int = 1_000_000
			
			let alicePayload = [UInt8](repeating: 0, count: payloadSize)
			let carolPayload = [UInt8](repeating: 1, count: payloadSize)
			
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(30)), FIFO<[UInt8], Swift.Error>())]
				let aliceInterface = try WGInterface<[UInt8]>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36001)
				
				let alicePeerFifo = FIFO<[UInt8], Swift.Error>()
				let carolPeerFifo = FIFO<[UInt8], Swift.Error>()
				let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36001, internalKeepAlive: .seconds(30)), alicePeerFifo), (PeerInfo(publicKey: carolPublicKey, ipAddress: "127.0.0.1", port: 36002, internalKeepAlive: .seconds(30)), carolPeerFifo)]
				let bobInterface = try WGInterface<[UInt8]>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36000)
				
				let carolPeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36000, internalKeepAlive: .seconds(30)), FIFO<[UInt8], Swift.Error>())]
				let carolInterface = try WGInterface<[UInt8]>(staticPrivateKey:carolPrivateKey, mtu:1400, initialConfiguration:carolPeers, logLevel:cliLogger.logLevel, listeningPort: 36002)

				foo.addTask {
					try await aliceInterface.run()
				}
				foo.addTask {
					try await bobInterface.run()
				}
				foo.addTask {
					try await carolInterface.run()
				}
				
				cliLogger.info("waiting for alice's interface to initialize...")
				try await aliceInterface.waitForChannelInit()
				
				cliLogger.info("waiting for bob's interface to initialize...")
				try await bobInterface.waitForChannelInit()
				
				cliLogger.info("waiting for carols's interface to initialize...")
				try await carolInterface.waitForChannelInit()
				
				cliLogger.info("Channel initialized. Alice sending handshake initiation message...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: alicePayload)
				
				cliLogger.info("Channel initialized. Carol sending handshake initiation message...")
				try await carolInterface.write(publicKey: bobPublicKey, data: carolPayload)
				
				cliLogger.info("Channel initialized. Reading data...")
				
				let aliceIterator = alicePeerFifo.makeAsyncConsumer()
				aliceRcvLoop: while(true) {
					if let incomingData = try await aliceIterator.next() {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == alicePayload)
						break aliceRcvLoop
					}
				}
				
				let carolIterator = carolPeerFifo.makeAsyncConsumer()
				carolRcvLoop: while(true) {
					if let incomingData = try await carolIterator.next() {
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == carolPayload)
						break carolRcvLoop
					}
				}

				foo.cancelAll()
			})
		}
	}
}
