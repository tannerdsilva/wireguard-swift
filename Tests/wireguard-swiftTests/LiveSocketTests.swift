import Testing
import Foundation
import RAW_dh25519
import RAW_base64
import RAW
import NIO
import Logging
import ServiceLifecycle
import wireguard_crypto_core
import bedrock_fifo
import bedrock_ip
@testable import wireguard_userspace_nio

struct DropXPercentOutbound:EncryptedPacketProcessor {
	var percent:Int
	mutating func willWriteOutbound(_ encryptedWireguardContent: inout ByteBuffer, ep:inout Endpoint) {
		if Int.random(in: 0..<100) < percent {
			encryptedWireguardContent.clear()
		}
	}
	mutating func willReadInbound(_ encryptedWireguardContent: inout Message.NIO) {}
}

struct DropInbound:EncryptedPacketProcessor {
	enum CaseType {
		case initiation
		case response
		case cookie
		case data
	}
	let endTime:NIODeadline
	let type:CaseType
	init(packetType:CaseType, lengthOfTime:TimeAmount) {
		type = packetType
		endTime = NIODeadline.now() + lengthOfTime
	}
	mutating func willWriteOutbound(_ encryptedWireguardContent: inout ByteBuffer, ep:inout Endpoint) {}
	mutating func willReadInbound(_ encryptedWireguardContent: inout Message.NIO) {
		switch encryptedWireguardContent {
			case .initiation(_):
				if(type == .initiation) {
					if(NIODeadline.now() < endTime) {
						let packet = Message.Initiation.Payload.Authenticated(RAW_staticbuff: Message.Initiation.Payload.Authenticated.RAW_staticbuff_zeroed())
						encryptedWireguardContent = .initiation(packet)
					}
				}
			case .response(_):
				if(type == .response) {
					if(NIODeadline.now() < endTime) {
						let packet = Message.Response.Payload.Authenticated(RAW_staticbuff: Message.Response.Payload.Authenticated.RAW_staticbuff_zeroed())
						encryptedWireguardContent = .response(packet)
					}
				}
			case .cookie(_):
				if(type == .cookie) {
					if(NIODeadline.now() < endTime) {
						let packet = Message.Cookie.Payload(RAW_staticbuff: Message.Cookie.Payload.RAW_staticbuff_zeroed())
						encryptedWireguardContent = .cookie(packet)
					}
				}
			case .data(_, _, _):
				if(type == .data) {
					if(NIODeadline.now() < endTime) {
						let recipeintIndex = PeerIndex(RAW_staticbuff: PeerIndex.RAW_staticbuff_zeroed())
						let counter = Counter(RAW_staticbuff: Counter.RAW_staticbuff_zeroed())
						let buffer = ByteBuffer().readableBytesView
						encryptedWireguardContent = .data(recipientIndex: recipeintIndex, counter: counter, payload: buffer)
					}
				}
			default:
				break
		}
	}
}

struct CorruptOutbound:EncryptedPacketProcessor {
	mutating func willWriteOutbound(_ encryptedWireguardContent: inout NIOCore.ByteBuffer, ep:inout Endpoint) {
		if Int.random(in: 0..<100) < 50 {
			let readable = encryptedWireguardContent.readableBytes
			guard readable > 0 else { return }
			
			let startIndex = readable / 2
			let corruptLength = readable - startIndex
			
			encryptedWireguardContent.withUnsafeMutableReadableBytes { ptr in
				guard let base = ptr.baseAddress else { return }
				
				let bytes = base.assumingMemoryBound(to: UInt8.self) // cast to UInt8 pointer
				for i in 0..<corruptLength {
					bytes[startIndex + i] ^= UInt8.random(in: 0...255)
				}
			}
		}
	}
	mutating func willReadInbound(_ encryptedWireguardContent: inout wireguard_crypto_core.Message.NIO) {}
}

struct DuplicateOutbound:EncryptedPacketProcessor {
	mutating func willWriteOutbound(_ encryptedWireguardContent: inout NIOCore.ByteBuffer, ep:inout Endpoint) {
		for _ in 0..<10 {
			var copy = encryptedWireguardContent
			encryptedWireguardContent.writeBuffer(&copy)
		}
	}
	mutating func willReadInbound(_ encryptedWireguardContent: inout wireguard_crypto_core.Message.NIO) {}
}

struct ChangeEndpoint:EncryptedPacketProcessor {
	mutating func willWriteOutbound(_ encryptedWireguardContent: inout NIOCore.ByteBuffer, ep:inout Endpoint) {
		if Int.random(in: 0..<100) < 25 {
			ep = Endpoint(Address("127.127.127.127")!, port: Endpoint.Port(RAW_native: 8008))
		}
	}
	mutating func willReadInbound(_ encryptedWireguardContent: inout wireguard_crypto_core.Message.NIO) {}
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
		
		let aliceBobSharedKey:MemoryGuarded<SharedKey>
		let bobAliceSharedKey:MemoryGuarded<SharedKey>

		let cliLogger:Logger

		init() throws {
			(alicePublicKey, alicePrivateKey) = (PublicKey(privateKey:Self.aliceStaticPrivateKey), Self.aliceStaticPrivateKey)
			(bobPublicKey, bobPrivateKey) = (PublicKey(privateKey:Self.bobStaticPrivateKey), Self.bobStaticPrivateKey)
			(carolPublicKey, carolPrivateKey) = (PublicKey(privateKey:Self.carolStaticPrivateKey), Self.carolStaticPrivateKey)
			aliceBobSharedKey = try dhKeyExchange(privateKey: alicePrivateKey, publicKey: bobPublicKey)
			bobAliceSharedKey = try dhKeyExchange(privateKey: bobPrivateKey, publicKey: alicePublicKey)
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = .debug
			cliLogger = buildLogger
		}
		
		fileprivate func runKCPTestInterfaces(foo: inout ThrowingTaskGroup<(), any Swift.Error>, alicePort:Int, bobPort:Int, ipAddress:String = "127.0.0.1") async throws -> (aliceInterface:WGInterface<KCPChannels>, bobInterface:WGInterface<KCPChannels>, aliceFifo:FIFO<ByteBuffer, Swift.Error>, bobFifo:FIFO<ByteBuffer, Swift.Error>) {
			let bobFifo = FIFO<ByteBuffer, Swift.Error>()
			let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: ipAddress, port: bobPort, internalKeepAlive: .seconds(20), inboundData: bobFifo)]
			let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: alicePort)
			
			let aliceFifo = FIFO<ByteBuffer, Swift.Error>()
			let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: ipAddress, port: alicePort, internalKeepAlive: .seconds(20), inboundData: aliceFifo)]
			let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: bobPort)
			
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
			return (aliceInterface, bobInterface, aliceFifo, bobFifo)
		}
		
		fileprivate func sendSinglePayload(payloadSize:Int, encryptedPacketProcessor: some EncryptedPacketProcessor) async throws {
			let payloadSize: Int = payloadSize
			
			let payload = [UInt8](repeating: 0, count: payloadSize)
			
			try await confirmation("verify the channels close", expectedCount:2) { closeConf in
				_ = try await withThrowingTaskGroup(body: { foo in
					let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36016, internalKeepAlive: .seconds(20), inboundData: FIFO<ByteBuffer, Swift.Error>())]
					let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36017, encryptedPacketProcessor: encryptedPacketProcessor)
					
					let aliceFifo = FIFO<ByteBuffer, Swift.Error>()
					let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36017, internalKeepAlive: .seconds(20), inboundData: aliceFifo)]
					let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36016, encryptedPacketProcessor: encryptedPacketProcessor)
					
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
					
					try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
						closeConf.confirm()
					}
					try await bobInterface.getChannel().closeFuture.whenComplete { _ in
						closeConf.confirm()
					}
					
					cliLogger.info("Channel initialized. Sending handshake initiation message...")
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
					
					cliLogger.info("Channel initialized. Reading data...")
					let iterator = aliceFifo.makeAsyncConsumer()
					while(true) {
						if let incomingDataBytes = try await iterator.next() {
							let incomingData = Array(incomingDataBytes.readableBytesView)
							cliLogger.debug("Received data that is \(incomingData.count) bytes long")
							#expect(incomingData == payload)
							foo.cancelAll()
							try await foo.waitForAll()
							return
						}
					}
				})
			}
		}
		
		@Test func confirmhandshakeSignals() async throws {
			let payloadSize: Int = 10
			let payload = [UInt8](repeating: 0, count: payloadSize)
			try await confirmation("verify the channels close", expectedCount:2) { closeConf in
				_ = try await withThrowingTaskGroup(body: { foo in
					let testInfo = try await runKCPTestInterfaces(foo: &foo, alicePort: 36003, bobPort: 36002)
					let aliceInterface = testInfo.aliceInterface; let bobInterface = testInfo.bobInterface
					
					try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
						closeConf.confirm()
					}
					try await bobInterface.getChannel().closeFuture.whenComplete { _ in
						closeConf.confirm()
					}
					
					let firstWrite = NIODeadline.now()
					cliLogger.info("alice is writing...")
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
					
					try await Task.sleep(for: .seconds(2))
					let secondWrite = NIODeadline.now()
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
					
					let aliceSignalIterator = await aliceInterface.getHandshakeFifo().makeAsyncConsumer()
					let bobSignalIterator = await bobInterface.getHandshakeFifo().makeAsyncConsumer()
					if let incomingSignal = try await aliceSignalIterator.next() {
						let ms = Double(incomingSignal.rtt.uptimeNanoseconds) / 1_000_000
						cliLogger.info("RTT: \(ms) ms")
						#expect(incomingSignal.recordedTime > firstWrite)
						#expect(incomingSignal.recordedTime < secondWrite)
						#expect(incomingSignal.rtt.uptimeNanoseconds > 0)
					}
					if let incomingSignal = try await bobSignalIterator.next() {
						let ms = Double(incomingSignal.rtt.uptimeNanoseconds) / 1_000_000
						cliLogger.info("RTT: \(ms) ms")
						#expect(incomingSignal.recordedTime > firstWrite)
						#expect(incomingSignal.recordedTime < secondWrite)
						#expect(incomingSignal.rtt.uptimeNanoseconds > 0)
					}
					
					foo.cancelAll()
					try await foo.waitForAll()
				})
			}
		}
		
		@Test func testPeerConfigurationUpdate() async throws {
			let payloadSize: Int = 10
			let payload = [UInt8](repeating: 0, count: payloadSize)
			try await confirmation("verify the channels close", expectedCount:2) { closeConf in
				_ = try await withThrowingTaskGroup(body: { foo in
					let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "48.48.48.48", port: 20202, internalKeepAlive: .seconds(1), inboundData: FIFO<ByteBuffer, Swift.Error>())]
					let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36005)
					
					let oldAliceFifo = FIFO<ByteBuffer, Swift.Error>()
					let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "48.48.48.48", port: 20202, internalKeepAlive: .seconds(1), inboundData: oldAliceFifo)]
					let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36004)
					
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
					
					try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
						closeConf.confirm()
					}
					try await bobInterface.getChannel().closeFuture.whenComplete { _ in
						closeConf.confirm()
					}
					
					foo.addTask {
						cliLogger.info("alice is writing...")
						try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
						cliLogger.info("data successfully sent")
					}
					
					let newAliceFifo = FIFO<ByteBuffer, Swift.Error>()
					let newBobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36005, internalKeepAlive: .seconds(1), inboundData: newAliceFifo)]
					let newAlicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36004, internalKeepAlive: .seconds(1), inboundData: FIFO<ByteBuffer, Swift.Error>())]
					foo.addTask {
						try await Task.sleep(for: .seconds(2))
						try await bobInterface.setConfiguration(peerConfig: newBobPeers)
						try await aliceInterface.setConfiguration(peerConfig: newAlicePeers)
						print()
					}
					
					let iterator = newAliceFifo.makeAsyncConsumer()
					if let incomingData = try await iterator.next() {
						cliLogger.info("Received data that is \(incomingData.readableBytes) bytes long")
						#expect(incomingData == ByteBuffer(bytes:payload))
					}
					
					foo.cancelAll()
					try await foo.waitForAll()
				})
			}
		}
		
 		@Test func testPeerDisconnect() async throws {
 			let payloadSize: Int = 10
 			let payload = [UInt8](repeating: 0, count: payloadSize)
 			try await confirmation("verify the channels close", expectedCount:3) { closeConf in
 				_ = try await withThrowingTaskGroup(body: { foo in
 					let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36004, internalKeepAlive: .seconds(1), inboundData: FIFO<ByteBuffer, Swift.Error>())]
 					let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36005)
					
 					let aliceFifo = FIFO<ByteBuffer, Swift.Error>()
 					let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36005, internalKeepAlive: .seconds(1), inboundData: aliceFifo)]
 					let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36004)
					
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
					
 					try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
 						closeConf.confirm()
 					}
 					try await bobInterface.getChannel().closeFuture.whenComplete { _ in
 						closeConf.confirm()
 					}
					
 					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
 					let iterator = aliceFifo.makeAsyncConsumer()
 					if let incomingDataBytes = try await iterator.next() {
 						let incomingData = Array(incomingDataBytes.readableBytesView)
 						cliLogger.info("Received data that is \(incomingData.count) bytes long")
 						#expect(incomingData == payload)
 					}
 					try await aliceInterface.close()
 					let newAliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36005)
 					foo.addTask {
 						try await newAliceInterface.run()
 					}
 					cliLogger.info("waiting for alice's interface to initialize...")
 					try await newAliceInterface.waitForChannelInit()
 					try await newAliceInterface.getChannel().closeFuture.whenComplete { _ in
 						closeConf.confirm()
 					}
 					try await newAliceInterface.write(publicKey: bobPublicKey, data: payload)
					
					if let incomingDataBytes = try await iterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						cliLogger.info("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == payload)
					}
					
 					foo.cancelAll()
 					try await foo.waitForAll()
 				})
 			}
 		}
	}
}

// MARK: Send Tests
extension WireguardSwiftTests.LiveSocketTests {
	@Test func sendSingleString() async throws {
		let stringToSend = "Hello, world!"
		let messageBytes: [UInt8] = Array(stringToSend.utf8)
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let testInfo = try await runKCPTestInterfaces(foo: &foo, alicePort: 36001, bobPort: 36000)
				let aliceInterface = testInfo.aliceInterface; let bobInterface = testInfo.bobInterface
				let aliceFifo = testInfo.aliceFifo
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				cliLogger.info("alice is writing...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: messageBytes)
				
				let iterator = aliceFifo.makeAsyncConsumer()
				if let incomingDataBytes = try await iterator.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.info("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == messageBytes)
				}
				foo.cancelAll()
				try await foo.waitForAll()
			})
		}
	}
	
	@Test func sendSmallStringSerialized() async throws {
		let stringToSend = "Hello world!"
		let messageBytes: [UInt8] = Array(stringToSend.utf8)
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let testInfo = try await runKCPTestInterfaces(foo: &foo, alicePort: 36007, bobPort: 36006)
				let aliceInterface = testInfo.aliceInterface; let bobInterface = testInfo.bobInterface
				let aliceFifo = testInfo.aliceFifo
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				foo.addTask {
					for _ in 0..<512 {
						cliLogger.trace("alice is writing a message...")
						let channel = try await aliceInterface.getChannel()
						try WGInterface<KCPChannels>.write(channel: channel, publicKey: bobPublicKey, data: ByteBuffer(bytes: messageBytes))
					}
				}
				
				var found = 0
				let iterator = aliceFifo.makeAsyncConsumer()
				rcvLoop: while(true) {
					if let incomingDataBytes = try await iterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						#expect(incomingData == messageBytes)
						found += 1
						cliLogger.info("bob received message from alice.", metadata:["message_count":"\(found)"])
						if found == 512 {
							foo.cancelAll()
							try await foo.waitForAll()
							break rcvLoop
						}
					}
				}
			})
		}
	}
	
	@Test func sendMultipleSmallMessages() async throws {
		let payloadSize: Int = 2000
		
		var tempPayload = [UInt8](repeating: 0, count: payloadSize)
		for i in 0..<payloadSize {
			tempPayload[i] = UInt8(i%256)
		}
		let payload1 = tempPayload
		let payload2 = tempPayload
		
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let testInfo = try await runKCPTestInterfaces(foo: &foo, alicePort: 36009, bobPort: 36008)
				let aliceInterface = testInfo.aliceInterface; let bobInterface = testInfo.bobInterface
				let aliceFifo = testInfo.aliceFifo
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				cliLogger.info("alice is sending the first data payload...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: payload1)
				
				cliLogger.info("alice is sending the second data payload...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: payload2)
				
				cliLogger.info("invoking read loop on primary task...")
				var count = 0
				let iterator = aliceFifo.makeAsyncConsumer()
				rcvLoop: while(true) {
					if let incomingDataBytes = try await iterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						if (count == 0) {
							cliLogger.debug("Received data that is \(incomingData.count) bytes long")
							#expect(incomingData == payload1)
							count += 1
						} else {
							cliLogger.debug("received data that is \(incomingData.count) bytes long")
							#expect(incomingData == payload2)
							foo.cancelAll()
							try await foo.waitForAll()
							break rcvLoop
						}
					}
				}
			})
		}
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
		
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let testInfo = try await runKCPTestInterfaces(foo: &foo, alicePort: 36011, bobPort: 36010)
				let aliceInterface = testInfo.aliceInterface; let bobInterface = testInfo.bobInterface
				let aliceFifo = testInfo.aliceFifo
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				cliLogger.info("Channel initialized. Sending handshake initiation message...")
				for payload in payloads {
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				}
				
				cliLogger.info("Channel initialized. Reading data...")
				var count = 0
				let iterator = aliceFifo.makeAsyncConsumer()
				rcvLoop: while true {
					if let incomingDataBytes = try await iterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == payloads[count])
						count += 1
						if (count == payloadCount - 1) {
							foo.cancelAll()
							try await foo.waitForAll()
							break rcvLoop
						}
					}
				}
			})
		}
	}

	@Test func sendSingleLargeMessage() async throws {
		try await sendSinglePayload(payloadSize: 20_000_000, encryptedPacketProcessor: DefaultEPP())
	}
	
	@Test func sendSinglePayloadWithSharedKey() async throws {
		let payloadSize: Int = 2_000_000
		
		let payload = [UInt8](repeating: 0, count: payloadSize)
		
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [PeerInfo(publicKey: bobPublicKey, sharedKey: bobAliceSharedKey, ipAddress: "127.0.0.1", port: 36016, internalKeepAlive: .seconds(20), inboundData: FIFO<ByteBuffer, Swift.Error>())]
				let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36017)
				
				let aliceFifo = FIFO<ByteBuffer, Swift.Error>()
				let bobPeers = [PeerInfo(publicKey: alicePublicKey, sharedKey: aliceBobSharedKey, ipAddress: "127.0.0.1", port: 36017, internalKeepAlive: .seconds(20), inboundData: aliceFifo)]
				let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36016)
				
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
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				cliLogger.info("Channel initialized. Sending handshake initiation message...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				
				cliLogger.info("Channel initialized. Reading data...")
				let iterator = aliceFifo.makeAsyncConsumer()
				while(true) {
					if let incomingDataBytes = try await iterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == payload)
						foo.cancelAll()
						try await foo.waitForAll()
						return
					}
				}
			})
		}
	}
	
	@Test func sendSimultaneousLargeMessages() async throws {
		let payloadSize: Int = 1_000_000
		let payload = [UInt8](repeating: 0, count: payloadSize)
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let testInfo = try await runKCPTestInterfaces(foo: &foo, alicePort: 36001, bobPort: 36000)
				let aliceInterface = testInfo.aliceInterface; let bobInterface = testInfo.bobInterface
				let aliceFifo = testInfo.aliceFifo;
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				foo.addTask {
					cliLogger.info("alice is writing...")
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				}
				
				foo.addTask {
					cliLogger.info("alice is writing...")
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				}
				
				for _ in 0..<2 {
					let iterator = aliceFifo.makeAsyncConsumer()
					if let incomingDataBytes = try await iterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						cliLogger.info("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == payload)
					}
				}
				
				foo.cancelAll()
				try await foo.waitForAll()
			})
		}
	}
	
	@Test func sendLargePayloadTwoWay() async throws {
		let payloadSize: Int = 1_000_000
		let payload = [UInt8](repeating: 0, count: payloadSize)
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let testInfo = try await runKCPTestInterfaces(foo: &foo, alicePort: 36001, bobPort: 36000)
				let aliceInterface = testInfo.aliceInterface; let bobInterface = testInfo.bobInterface
				let aliceFifo = testInfo.aliceFifo; let bobFifo = testInfo.bobFifo
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				foo.addTask {
					cliLogger.info("alice is writing...")
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				}
				
				foo.addTask {
					cliLogger.info("bob is writing...")
					try await bobInterface.write(publicKey: alicePublicKey, data: payload)
				}
				
				let aliceIterator = aliceFifo.makeAsyncConsumer()
				if let incomingDataBytes = try await aliceIterator.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.info("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload)
				}
				
				let bobIterator = bobFifo.makeAsyncConsumer()
				if let incomingDataBytes = try await bobIterator.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.info("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload)
				}
				
				foo.cancelAll()
				try await foo.waitForAll()
			})
		}
	}
	
	@Test func sendFromMultiplePeers() async throws {
		let payloadSize: Int = 1_000_000
		
		let alicePayload = [UInt8](repeating: 0, count: payloadSize)
		let carolPayload = [UInt8](repeating: 1, count: payloadSize)
		
		try await confirmation("verify the channels close", expectedCount:3) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36012, internalKeepAlive: .seconds(20), inboundData: FIFO<ByteBuffer, Swift.Error>())]
				let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36013)
				
				let alicePeerFifo = FIFO<ByteBuffer, Swift.Error>()
				let carolPeerFifo = FIFO<ByteBuffer, Swift.Error>()
				let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36013, internalKeepAlive: .seconds(30), inboundData: alicePeerFifo), PeerInfo(publicKey: carolPublicKey, ipAddress: "127.0.0.1", port: 36014, internalKeepAlive: .seconds(30), inboundData: carolPeerFifo)]
				let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36012)
				
				let carolPeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36012, internalKeepAlive: .seconds(30), inboundData: FIFO<ByteBuffer, Swift.Error>())]
				let carolInterface = try WGInterface<KCPChannels>(staticPrivateKey:carolPrivateKey, mtu:1400, initialConfiguration:carolPeers, logLevel:cliLogger.logLevel, listeningPort: 36014)
				
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
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await carolInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				cliLogger.info("Channel initialized. Alice sending handshake initiation message...")
				try await aliceInterface.write(publicKey: bobPublicKey, data: alicePayload)
				
				cliLogger.info("Channel initialized. Carol sending handshake initiation message...")
				try await carolInterface.write(publicKey: bobPublicKey, data: carolPayload)
				
				cliLogger.info("Channel initialized. Reading data...")
				
				let aliceIterator = alicePeerFifo.makeAsyncConsumer()
				aliceRcvLoop: while(true) {
					if let incomingDataBytes = try await aliceIterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == alicePayload)
						break aliceRcvLoop
					}
				}
				
				let carolIterator = carolPeerFifo.makeAsyncConsumer()
				carolRcvLoop: while(true) {
					if let incomingDataBytes = try await carolIterator.next() {
						let incomingData = Array(incomingDataBytes.readableBytesView)
						cliLogger.debug("Received data that is \(incomingData.count) bytes long")
						#expect(incomingData == carolPayload)
						break carolRcvLoop
					}
				}
				
				foo.cancelAll()
			})
		}
	}
	
	@Test func sendAroundMultiplePeers() async throws {
		let payloadSize: Int = 100_000
		
		let payload1 = [UInt8](repeating: 0, count: payloadSize)
		let payload2 = [UInt8](repeating: 1, count: payloadSize+1)
		let payload3 = [UInt8](repeating: 1, count: payloadSize+2)
		
		try await confirmation("verify the channels close", expectedCount:3) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let aliceFifoB = FIFO<ByteBuffer, Swift.Error>()
				let aliceFifoC = FIFO<ByteBuffer, Swift.Error>()
				let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36012, internalKeepAlive: .seconds(20), inboundData: aliceFifoB), PeerInfo(publicKey: carolPublicKey, ipAddress: "127.0.0.1", port: 36014, internalKeepAlive: .seconds(20), inboundData: aliceFifoC)]
				let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36013)
				
				let bobFifoA = FIFO<ByteBuffer, Swift.Error>()
				let bobFifoC = FIFO<ByteBuffer, Swift.Error>()
				let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36013, internalKeepAlive: .seconds(30), inboundData: bobFifoA), PeerInfo(publicKey: carolPublicKey, ipAddress: "127.0.0.1", port: 36014, internalKeepAlive: .seconds(30), inboundData: bobFifoC)]
				let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36012)
				
				let carolFifoA = FIFO<ByteBuffer, Swift.Error>()
				let carolFifoB = FIFO<ByteBuffer, Swift.Error>()
				let carolPeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36012, internalKeepAlive: .seconds(30), inboundData: carolFifoB), PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36013, internalKeepAlive: .seconds(30), inboundData: carolFifoA)]
				let carolInterface = try WGInterface<KCPChannels>(staticPrivateKey:carolPrivateKey, mtu:1400, initialConfiguration:carolPeers, logLevel:cliLogger.logLevel, listeningPort: 36014)
				
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
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await carolInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				cliLogger.info("Channel initialized. Sending Data...")
				foo.addTask {
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload1)
				}
				foo.addTask {
					try await aliceInterface.write(publicKey: carolPublicKey, data: payload2)
				}
				foo.addTask {
					try await bobInterface.write(publicKey: alicePublicKey, data: payload3)
				}
				foo.addTask {
					try await bobInterface.write(publicKey: carolPublicKey, data: payload3)
				}
				foo.addTask {
					try await carolInterface.write(publicKey: bobPublicKey, data: payload2)
				}
				foo.addTask {
					try await carolInterface.write(publicKey: alicePublicKey, data: payload1)
				}
				cliLogger.info("Reading data...")
				
				let aliceIteratorB = aliceFifoB.makeAsyncConsumer()
				if let incomingDataBytes = try await aliceIteratorB.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.debug("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload3)
				}
				
				let aliceIteratorC = aliceFifoC.makeAsyncConsumer()
				if let incomingDataBytes = try await aliceIteratorC.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.debug("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload1)
				}
				
				let bobIteratorA = bobFifoA.makeAsyncConsumer()
				if let incomingDataBytes = try await bobIteratorA.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.debug("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload1)
				}
				
				let bobIteratorC = bobFifoC.makeAsyncConsumer()
				if let incomingDataBytes = try await bobIteratorC.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.debug("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload2)
				}
				
				let carolIteratorA = carolFifoA.makeAsyncConsumer()
				if let incomingDataBytes = try await carolIteratorA.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.debug("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload2)
				}
				
				let carolIteratorB = carolFifoB.makeAsyncConsumer()
				if let incomingDataBytes = try await carolIteratorB.next() {
					let incomingData = Array(incomingDataBytes.readableBytesView)
					cliLogger.debug("Received data that is \(incomingData.count) bytes long")
					#expect(incomingData == payload3)
				}
				
				foo.cancelAll()
			})
		}
	}
}

// MARK: Packet Modification Tests
extension WireguardSwiftTests.LiveSocketTests {
	@Test func testDropXPercentOutbound() async throws {
		try await sendSinglePayload(payloadSize: 10_000_000, encryptedPacketProcessor: DropXPercentOutbound(percent: 10))
	}
	
	@Test func testDropInboundInitiationPackets() async throws {
		try await sendSinglePayload(payloadSize: 10, encryptedPacketProcessor: DropInbound(packetType: .initiation, lengthOfTime: .seconds(120)))
	}
	
	@Test func testDropInboundResponsePackets() async throws {
		try await sendSinglePayload(payloadSize: 10, encryptedPacketProcessor: DropInbound(packetType: .response, lengthOfTime: .seconds(120)))
	}
	
	@Test func testDropInboundDataPackets() async throws {
		try await sendSinglePayload(payloadSize: 10000, encryptedPacketProcessor: DropInbound(packetType: .data, lengthOfTime: .seconds(10)))
	}
	
	@Test func testCorruptOutbound() async throws {
		try await sendSinglePayload(payloadSize: 10000, encryptedPacketProcessor: CorruptOutbound())
	}
	
	@Test func testEndpointChange() async throws {
		try await sendSinglePayload(payloadSize: 10000, encryptedPacketProcessor: ChangeEndpoint())
	}
}

// MARK: Custom Channel Tests
extension WireguardSwiftTests.LiveSocketTests {
	@Test func testDefaultChannel() async throws {
		let payloadSize: Int = 10
		let payload = [UInt8](repeating: 0, count: payloadSize)
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36004, internalKeepAlive: .seconds(1), inboundData: FIFO<ByteBuffer, Swift.Error>())]
				let aliceInterface = try WGInterface<DefaultChannels>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, customChannelArgs: cliLogger.logLevel, listeningPort: 36005)
				
				let aliceFifo = FIFO<ByteBuffer, Swift.Error>()
				let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36005, internalKeepAlive: .seconds(1), inboundData: aliceFifo)]
				let bobInterface = try WGInterface<DefaultChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, customChannelArgs: cliLogger.logLevel, listeningPort: 36004)
				
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
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}

				try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				
				let iterator = aliceFifo.makeAsyncConsumer()
				if let incomingData = try await iterator.next() {
					cliLogger.info("Received data that is \(incomingData.readableBytes) bytes long")
				}
				
				foo.cancelAll()
				try await foo.waitForAll()
			})
		}
	}
	
	@Test func testKeepAliveChannel() async throws {
		let payloadSize: Int = 10
		let payload = [UInt8](repeating: 0, count: payloadSize)
		try await confirmation("verify the channels close", expectedCount:2) { closeConf in
			_ = try await withThrowingTaskGroup(body: { foo in
				let alicePeers = [PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 36004, internalKeepAlive: .seconds(1), inboundData: FIFO<ByteBuffer, Swift.Error>())]
				let aliceInterface = try WGInterface<KeepAlive>(staticPrivateKey:alicePrivateKey, mtu:1400, initialConfiguration:alicePeers, logLevel:cliLogger.logLevel, listeningPort: 36005)
				
				let aliceFifo = FIFO<ByteBuffer, Swift.Error>()
				let bobPeers = [PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 36005, internalKeepAlive: .seconds(1), inboundData: aliceFifo)]
				let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey:bobPrivateKey, mtu:1400, initialConfiguration:bobPeers, logLevel:cliLogger.logLevel, listeningPort: 36004)
				
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
				
				try await aliceInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				try await bobInterface.getChannel().closeFuture.whenComplete { _ in
					closeConf.confirm()
				}
				
				try await aliceInterface.setConfiguration(peerConfig: alicePeers)
				try await bobInterface.write(publicKey: alicePublicKey, data: payload)
				do {
					try await aliceInterface.write(publicKey: bobPublicKey, data: payload)
				} catch {}

				try await Task.sleep(for:.seconds(1))
				let aliceSignalIterator = await aliceInterface.getHandshakeFifo().makeAsyncConsumer()
				let bobSignalIterator = await bobInterface.getHandshakeFifo().makeAsyncConsumer()
				if let _ = try await aliceSignalIterator.next() { }
				if let _ = try await bobSignalIterator.next() { }
				
				foo.cancelAll()
				try await foo.waitForAll()
			})
		}
	}
}
