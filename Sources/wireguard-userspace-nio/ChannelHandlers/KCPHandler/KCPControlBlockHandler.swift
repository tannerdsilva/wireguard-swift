import NIO
import RAW
import RAW_dh25519
import RAW_blake2
import Logging
import wireguard_crypto_core

enum KCPError:Swift.Error {
	/// The connection has been declared dead (max retransmits hit).
	case deadLink
	/// There are no control blocks active
	case noControlBlocks
}

@RAW_staticbuff(bytes: 4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian: true)
struct MagicID:Sendable {}

internal final class KcpControlBlockHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PeerAssociated<KCPSegment>
	internal typealias InboundOut = (PublicKey, ByteBuffer)
	
	internal typealias OutboundIn = (PublicKey, ByteBuffer)
	internal typealias OutboundOut = PeerAssociated<KCPSegment>
	
	// kcp control blocks: index 0 is the newest control block
	private var kcp:[PublicKey:[KCPControlBlock]] = [:]
	private var frozenTime:UInt64 = 0
	private var updateTask:RepeatedTask?
	private var kcpUpdateTime:TimeAmount = .milliseconds(50)

	private var buffer:ByteBuffer
	
    private let ourKey:PublicKey
	private let logger:Logger

	var count = 0
		
	internal init(key:MemoryGuarded<PrivateKey>, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger

        ourKey = PublicKey(privateKey: key)
		buffer = ByteBuffer()
	}

	private func scheduleRepeatedKCPUpdates(context:ChannelHandlerContext) {
		if updateTask != nil {
			updateTask!.cancel()
			logger.trace("kcp update task task cancelled")
		}
		
		updateTask = context.eventLoop.scheduleRepeatedTask(initialDelay: .seconds(0), delay: kcpUpdateTime) {
			[weak self, l = logger, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			l.trace("kcp update triggered")
			for (key, _) in kcp {
				c.accessContext({ contextPointer in
					writeOutboundOut(key: key, context: contextPointer.pointee)
//					if(kcp[key]![0].delay != 0) {
//						print(kcp[key]![0].delay)
//					}
				})
			}
		}

		logger.debug("kcp update task scheduled")
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
	internal func channelReadComplete(context: ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.fireChannelReadComplete()
	}
	
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let data = unwrapInboundIn(data)
		let key = data.publicKey

		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: ourKey, key2: key)
			kcp[key, default: []].append(KCPControlBlock(conv: magicID))
			kcp[key]![0].setNoDelay(1, nc:0)
			scheduleRepeatedKCPUpdates(context: context)
		}
        
		// imp segment
		do {
			logger.trace("Received kcp segment", metadata: ["seg len": "\(data.associatedValue.header.dataLength) bytes"])
			let inboundOutBuffers = try input(key: key, segment: data.associatedValue, context: context)
			for buffer in inboundOutBuffers {
				context.fireChannelRead(wrapInboundOut((key, buffer)))
			}
		} catch let error {
			logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
}

// Channel Write
extension KcpControlBlockHandler {
	internal func flush(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		logger.trace("caught flush signal.")
	}

	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: key, key2: ourKey)
			kcp[key, default: []].append(KCPControlBlock(conv: magicID))
			kcp[key]![0].setNoDelay(1, nc:0)
			scheduleRepeatedKCPUpdates(context: context)
		}

		// Send data to control block
		do {
			logger.trace("Sending kcp segment", metadata: ["size": "\(data.readableBytes) bytes"])
			_ = self.kcp[key]![0].send(data, ackPromise: promise)
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

extension KcpControlBlockHandler {
	func channelWritabilityChanged(context: ChannelHandlerContext) {
		defer {
			context.fireChannelWritabilityChanged()
		}
		logger.debug("kcp handler writability changed", metadata: ["isWritable":"\(context.channel.isWritable)"])
		if(context.channel.isWritable) {
			for k in kcp.keys {
				for i in 0..<kcp[k]!.count {
					kcp[k]![i].delay += NIODeadline.now().uptimeNanoseconds - frozenTime
				}
			}
			scheduleRepeatedKCPUpdates(context: context)
		} else {
			if(updateTask != nil) {
				frozenTime = NIODeadline.now().uptimeNanoseconds
				logger.debug("Cancelling repeated scheduled task")
				updateTask!.cancel()
			}
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

	private func writeOutboundOut(key:PublicKey, context: ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif

		var i = 0
		var isWritten = false
		while i < kcp[key]!.count {
			let outboundOutSegments = kcp[key]![i].getOutboundSegments(byteBuffer: &buffer)

			for segment in outboundOutSegments {
				logger.trace("writing kcp segment to next handler in pipeline.", metadata:["public-key_remote":"\(key)", "segment_sequence_number":"\(segment.0.header.sequenceNumber)", "segment_command":"\(segment.0.header.command)", "segment_data_length":"\(segment.0.header.dataLength)", "segment_fragment_id":"\(segment.0.header.fragmentID)", "segment_timestamp":"\(segment.0.header.timestamp)", "segment_una":"\(segment.0.header.una)"])
				context.write(wrapOutboundOut(PeerAssociated<KCPSegment>(publicKey: key, segment: segment.0)), promise: segment.1)
				isWritten = true
			}
			i += 1
		}
		context.flush()
	}

	private func input(key:PublicKey, segment: KCPSegment, context:ChannelHandlerContext) throws -> [ByteBuffer]{
		for i in 0..<kcp[key]!.count {
			do {
				return try kcp[key]![i].input(segment, context: context)
			} catch {
				continue
			}
		}
		return []
	}
}
