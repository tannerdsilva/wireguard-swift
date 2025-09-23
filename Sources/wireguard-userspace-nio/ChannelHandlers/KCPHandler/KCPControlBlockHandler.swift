import NIO
import RAW
import RAW_dh25519
import RAW_blake2
import Logging
import wireguard_crypto_core

enum KCPError: Swift.Error {
	/// The connection has been declared dead (max retransmits hit).
	case deadLink
	/// There are no control blocks active
	case noControlBlocks
}

@RAW_staticbuff(bytes: 4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian: true)
struct MagicID:Sendable {}

internal final class KcpControlBlockHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PeerSegment
	internal typealias InboundOut = (PublicKey, ByteBuffer)
	
	internal typealias OutboundIn = (PublicKey, ByteBuffer)
	internal typealias OutboundOut = PeerSegment
	
	// kcp control blocks: index 0 is the newest control block
	private var kcp:[PublicKey:[KCPControlBlock]] = [:]
	private var updateTasks:[PublicKey:RepeatedTask] = [:]
	private var kcpUpdateTime:TimeAmount = .milliseconds(30)

	private var buffer:ByteBuffer
	
    private let ourKey:PublicKey
	private let logger:Logger
		
	internal init(key:MemoryGuarded<PrivateKey>, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger

        ourKey = PublicKey(privateKey: key)
		buffer = ByteBuffer()
	}

	private func kcpUpdates(key:PublicKey, context:ChannelHandlerContext) {
		if updateTasks[key] != nil {
			updateTasks[key]!.cancel()
		}
		
		updateTasks[key] = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			flush(key: key, context: context)
			
			rcvLoop: while true {
				do {
					if(kcp[key]!.isEmpty) {
						throw KCPError.noControlBlocks
					}

					let receivedData = try kcp[key]![kcp[key]!.count-1].receive()
					
					logger.debug("Compiled kcp message. Passing to splicer.", metadata: ["size": "\(receivedData.readableBytes) bytes"])
					c.accessContext { contextPointer in
						contextPointer.pointee.fireChannelRead(wrapInboundOut((key, receivedData)))
					}
				} catch { break rcvLoop } // received no data or it failed
			}
		}
	}
	
}

// Basic Events
extension KcpControlBlockHandler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		logger.trace("handler added to NIO pipeline.")
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		logger.trace("handler removed from NIO pipeline.")
	}	
}

// Channel Read
extension KcpControlBlockHandler {
	// Receiving kcp segment
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let data = unwrapInboundIn(data)
		let key = data.publicKey

		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: ourKey, key2: key)
			kcp[key, default: []].append(KCPControlBlock(conv: magicID))
			kcp[key]![0].setNoDelay(1, interval: 30, resend: 1, nc:0)
			kcpUpdates(key: key, context: context)
		}
        
		// Input segment
		do {
			logger.trace("Received kcp segment", metadata: ["seg len": "\(data.segment.header.dataLength) bytes"])
			try input(key: key, segment: data.segment)
		} catch let error {
			logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
}

// Channel Write
extension KcpControlBlockHandler {
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: key, key2: ourKey)
			kcp[key, default: []].append(KCPControlBlock(conv: magicID))
			kcp[key]![0].setNoDelay(1, interval: 30, resend: 1, nc:0)
			kcpUpdates(key: key, context: context)
		}

		// Send data to control block
		do {
			logger.trace("Sending kcp segment", metadata: ["size": "\(data.readableBytes) bytes"])
			_ = try kcp[key]![0].send(data, ackPromise: promise)
		} catch {
			logger.error("Error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
}

// Channel user events
extension KcpControlBlockHandler {
	// Inbound events (Handshake Reset)
	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as WireguardHandler.WireguardHandshakeNotification:
				logger.debug("Resetting kcp", metadata: ["public-key_remote":"\(evt.publicKey)"])
				// Need to figure out how to make this into a conversation id
				let key = evt.publicKey
				
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}

// Control Block Helper Functions
extension KcpControlBlockHandler {

	private func magicID(key1:PublicKey, key2:PublicKey) throws -> UInt32 {
		var hasher = try WGHasher<MagicID>()
		try hasher.update(key1)
		try hasher.update(key2)
		var h = try hasher.finish()
		return h.RAW_native()
	}

	private func flush(key:PublicKey, context: ChannelHandlerContext) {
		var i = 0
		while i < kcp[key]!.count {
			let remove = kcp[key]![i].flush(current: iclock(), byteBuffer: &buffer, key: key, context: context, wrapOut: wrapOutboundOut)

			i += 1
		}
	}

	private func input(key:PublicKey, segment: KCPSegment) throws {
		for i in 0..<kcp[key]!.count {
			do {
				try kcp[key]![i].input(segment)
			} catch {
				continue
			}
		}
	}
}