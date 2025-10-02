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
	internal typealias InboundOut = PeerAssociated<ByteBuffer>
	
	internal typealias OutboundIn = PeerAssociated<ByteBuffer>
	internal typealias OutboundOut = PeerAssociated<KCPSegment>
	
	// kcp control blocks: index 0 is the newest control block
	private var kcp:[PublicKey:[KCPControlBlock]] = [:]
	private var updateTask:RepeatedTask?
	private var kcpUpdateTime:TimeAmount = .milliseconds(30)

	private var buffer:ByteBuffer
	
    private let ourKey:PublicKey
	private let logger:Logger

	let mtu:Int
	var count = 0
		
	internal init(key:MemoryGuarded<PrivateKey>, mtu:Int = 1400, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger

        ourKey = PublicKey(privateKey: key)
		buffer = ByteBuffer()
		self.mtu = mtu
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
					for i in  0..<kcp[key]!.count {
						kcp[key]![i].resendAndProbe(context: contextPointer.pointee, handler: self)
					}
					contextPointer.pointee.flush()
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
			kcp[key, default: []].append(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), logLevel: logger.logLevel))
			scheduleRepeatedKCPUpdates(context: context)
		}
        
		// imp segment
		logger.trace("Received kcp segment", metadata: ["seg len": "\(data.associatedValue.header.dataLength) bytes"])
		for i in 0..<kcp[key]!.count {
			do {
				try kcp[key]![i].handleChannelRead(context: context, handler: self, associatedSegment: data)
			} catch {
				continue
			}
		}
	}
}

// Channel Write
extension KcpControlBlockHandler {
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var data = unwrapOutboundIn(data)
		let key = data.publicKey
		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: key, key2: ourKey)
			kcp[key, default: []].append(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), logLevel: logger.logLevel))
			scheduleRepeatedKCPUpdates(context: context)
		}

		// Send data to control block
		do {
			logger.trace("Sending kcp segment", metadata: ["size": "\(data.associatedValue.readableBytes) bytes"])
			self.kcp[key]![0].handleWrite(context: context, handler: self, message: data.associatedValue, writePromise: promise)
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
		if (context.channel.isWritable) {
			scheduleRepeatedKCPUpdates(context: context)
		} else {
			if (updateTask != nil) {
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
}
