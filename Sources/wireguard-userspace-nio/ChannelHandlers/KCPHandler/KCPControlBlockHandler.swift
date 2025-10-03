import NIO
import RAW
import RAW_dh25519
import RAW_blake2
import Logging
import wireguard_crypto_core

@RAW_staticbuff(bytes: 4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
internal struct MagicID:Sendable {}

@available(*, deprecated, renamed:"KCPControlBlock.Handler")
internal typealias KcpControlBlockHandler = KCPControlBlock.Handler

internal final class KCPLivePeer {
	/// the rolling set of control blocks associated with this peer. index 0 is the newest control block.
	private var controlBlocks:[KCPControlBlock] = []
	
	private let logger:Logger
	private let mtu:Int
	
	init(mtu:Int, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:KCPControlBlock.self)).\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		
		self.mtu = mtu
	}
	
	internal var count:Int {
		get {
			return controlBlocks.count
		}
	}

	internal func insertLatestControlBlock(_ block:KCPControlBlock) {
		controlBlocks.insert(block, at:0)
		if(controlBlocks.count == 1) {
			controlBlocks[0].isActiveReceiver = true
		}
		for i in 0..<controlBlocks.count {
			if(controlBlocks[i].isActiveReceiver) {
				logger.debug("Inserting new control block", metadata: ["activeBlock": "\(i)"])
			}
		}
		
	}

	internal func handleWrite(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, message: ByteBuffer, writePromise: EventLoopPromise<Void>? = nil, ackPromise: EventLoopPromise<Void>? = nil) throws {
		controlBlocks[0].handleWrite(context: context, handler: handler, message: message, writePromise: writePromise, ackPromise: ackPromise)
	}

	internal func handleChannelRead(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, associatedSegment:PeerAssociated<KCPSegment>) {
		cbLoop: for i in 0..<controlBlocks.count {
			do {
				try controlBlocks[i].handleChannelRead(context: context, handler: handler, associatedSegment: associatedSegment)
				break cbLoop
			} catch {
				continue
			}
		}
		rotateActiveControlBlock(context: context, handler: handler)
	}

	internal func resendAndProbe(context:ChannelHandlerContext, handler:KCPControlBlock.Handler) {
		for i in  0..<controlBlocks.count {
			controlBlocks[i].resendAndProbe(context: context, handler: handler)
		}
		context.flush()
	}
	
	internal func rotateActiveControlBlock(context:ChannelHandlerContext, handler:KCPControlBlock.Handler) {
		guard controlBlocks.count >= 2 else {
			guard controlBlocks.count == 1 else {
				return
			}
			controlBlocks[0].isActiveReceiver = true
			return 
		}
		for i in 1..<(controlBlocks.count) {
			if (controlBlocks[i].isActiveReceiver && controlBlocks[i].isInactive) {
				controlBlocks[i].isActiveReceiver = false
				controlBlocks[i-1].isActiveReceiver = true
				controlBlocks[i-1].writeAllInboundOut(handler: handler, context: context)
				logger.debug("Rotating control block", metadata: ["newActiveIndex": "\(i-1)"])
				return
			}
		}
	}
}


extension KCPControlBlock {
	internal final class Handler:ChannelDuplexHandler, @unchecked Sendable {
		internal typealias InboundIn = PeerAssociated<KCPSegment>
		internal typealias InboundOut = PeerAssociated<ByteBuffer>
		
		internal typealias OutboundIn = PeerAssociated<ByteBuffer>
		internal typealias OutboundOut = PeerAssociated<KCPSegment>
		
		// kcp control blocks: index 0 is the newest control block
		private var kcp:[PublicKey:KCPLivePeer] = [:]
		private var updateTask:RepeatedTask?
		private var kcpUpdateTime:TimeAmount = .milliseconds(30)
		
		private let ourKey:PublicKey
		private let logger:Logger

		let mtu:Int
		var count = 0
			
		internal init(key:MemoryGuarded<PrivateKey>, mtu:Int = 1400, logLevel:Logger.Level) {
			var buildLogger = Logger(label:"\(String(describing:KCPControlBlock.self)).\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			logger = buildLogger

			ourKey = PublicKey(privateKey:key)
			self.mtu = mtu
		}

		private func scheduleRepeatedKCPUpdates(context:ChannelHandlerContext) {
			if updateTask != nil {
				updateTask!.cancel()
				logger.trace("kcp update task task cancelled")
			}
			
			updateTask = context.eventLoop.scheduleRepeatedTask(initialDelay: .seconds(0), delay: kcpUpdateTime) {
				[weak self, c = ContextContainer(context:context)] _ in
				guard let self = self else { return }
				for (key, _) in kcp {
					c.accessContext({ contextPointer in
						kcp[key]!.resendAndProbe(context: contextPointer.pointee, handler: self)
					})
				}
			}

			logger.debug("kcp update task scheduled")
		}
		
	}
}

// Basic Events
extension KCPControlBlock.Handler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		logger.trace("handler added to NIO pipeline.")
		scheduleRepeatedKCPUpdates(context: context)
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		logger.trace("handler removed from NIO pipeline.")
	}	
}

// Channel Read
extension KCPControlBlock.Handler {
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
			kcp[key] = KCPLivePeer(mtu: mtu, logLevel: logger.logLevel)
			kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), logLevel: logger.logLevel))
		}
		
		// input segment
		logger.trace("Received kcp segment", metadata: ["seg len": "\(data.associatedValue.header.dataLength) bytes"])
		kcp[key]!.handleChannelRead(context: context, handler: self, associatedSegment: data)
	}
}

// Channel Write
extension KCPControlBlock.Handler {
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let data = unwrapOutboundIn(data)
		let key = data.publicKey
		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: key, key2: ourKey)
			kcp[key] = KCPLivePeer(mtu: mtu, logLevel: logger.logLevel)
			kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), logLevel: logger.logLevel))
		}

		// Send data to control block
		do {
			logger.trace("Sending kcp segment", metadata: ["size": "\(data.associatedValue.readableBytes) bytes"])
			try kcp[key]!.handleWrite(context: context, handler: self, message: data.associatedValue, writePromise: promise, ackPromise:nil)
		} catch {
			logger.error("Error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
}

// Channel user events
extension KCPControlBlock.Handler {
	// Inbound events (Handshake Reset)
	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as WireguardHandler.WireguardHandshakeNotification:
				logger.debug("Resetting kcp", metadata: ["public-key_remote":"\(evt.publicKey)"])
				// Need to figure out how to make this into a conversation id
				let key = evt.publicKey
				let convID = evt.geometry.initiator.RAW_native()
				// Check if control block exists
				if (kcp[key] == nil) {
					// Create the magic id control block
					let magicID = try! magicID(key1: ourKey, key2: key)
					kcp[key] = KCPLivePeer(mtu: mtu, logLevel: logger.logLevel)
					kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), logLevel: logger.logLevel))
				}
				kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: convID, mtu: UInt32(mtu), logLevel: logger.logLevel))
				
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}

extension KCPControlBlock.Handler {
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
extension KCPControlBlock.Handler {
	private func magicID(key1:PublicKey, key2:PublicKey) throws -> UInt32 {
		var hasher = try WGHasher<MagicID>()
		try hasher.update(key1)
		try hasher.update(key2)
		var h = try hasher.finish()
		return h.RAW_native()
	}
}
