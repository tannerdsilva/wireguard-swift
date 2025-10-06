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
	/// the rolling set of control blocks associated with this peer. index 0 is the newest control block. Index count-1 reserved for the magic ID control block
	internal var controlBlocks:[KCPControlBlock] = []
	
	private let logger:Logger
	private let mtu:UInt16

	private var mssMeter:KCPControlBlock.MSSMeter
	
	init(mtu:UInt16, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:KCPControlBlock.self)).\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		self.mtu = mtu
		self.mssMeter = KCPControlBlock.MSSMeter(maxSamples:128)
	}
	
	internal var count:Int {
		get {
			return controlBlocks.count
		}
	}

	internal func insertLatestControlBlock(_ block:KCPControlBlock) {
		controlBlocks.insert(block, at:0)
		if(count == 1) {
			controlBlocks[0].isActiveReceiver = true
		}
		for i in 0..<count {
			if(controlBlocks[i].isActiveReceiver) {
				logger.debug("Inserting new control block", metadata: ["activeConvID": "\(controlBlocks[i].conv)"])
			}
		}
		
	}

	internal func handleWrite(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, message: ByteBuffer, writePromise: EventLoopPromise<Void>? = nil, ackPromise: EventLoopPromise<Void>? = nil) throws {
		controlBlocks[0].handleWrite(context: context, handler: handler, mssMeter: &mssMeter, message: message, writePromise: writePromise, ackPromise: ackPromise)
	}

	internal func handleChannelRead(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, associatedSegment:PeerAssociated<KCPSegment>, now:NIODeadline) -> Bool {
		cbLoop: for i in 0..<count {
			do {
				guard associatedSegment.associatedValue.header.conversationID == controlBlocks[i].conv else {
					continue cbLoop
				}
				try controlBlocks[i].handleChannelRead(context: context, handler: handler, associatedSegment: associatedSegment, now:now)
				// Check for disconnection via magicID
				if(i == count - 1 && !controlBlocks[count - 1].isActiveReceiver) {
					return false
				}
				break cbLoop
			} catch {
				continue
			}
		}
		rotateActiveControlBlock(context: context, handler: handler)
		return true
	}

	internal func resendAndProbe(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, now:NIODeadline) {
		for i in  0..<count {
			controlBlocks[i].resendAndProbe(context: context, handler: handler, now:now)
			controlBlocks[i].recomputeEffectiveWindow(context:context, mssMeter:&mssMeter)
		}
		context.flush()
	}
	
	internal func rotateActiveControlBlock(context:ChannelHandlerContext, handler:KCPControlBlock.Handler) {
		guard count >= 2 else {
			guard count == 1 else {
				return
			}
			controlBlocks[0].isActiveReceiver = true
			return 
		}
		for i in 1..<(count) {
			if (controlBlocks[i].isActiveReceiver && controlBlocks[i].isInactive) {
				controlBlocks[i].isActiveReceiver = false
				controlBlocks[i-1].isActiveReceiver = true
				controlBlocks[i-1].writeAllInboundOut(handler: handler, context: context)
				logger.debug("Rotating control block", metadata: ["newActiveConvID": "\(controlBlocks[i-1].conv)"])
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
		private var updateTask:RepeatedTask? {
			didSet {
				if oldValue != nil {
					oldValue!.cancel()
					logger.trace("kcp update task task cancelled")
				}
			}
		}
		private var kcpUpdateTime:TimeAmount = .milliseconds(30)
		
		private let ourKey:PublicKey
		private let logger:Logger

		let mtu:UInt16
		var count = 0

		private var readWindow:Int!
		private var writeWindow:Int!
			
		internal init(key:MemoryGuarded<PrivateKey>, mtu:inout UInt16, logLevel:Logger.Level) {
			var buildLogger = Logger(label:"\(String(describing:KCPControlBlock.self)).\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			buildLogger[metadataKey:"public-key_self"] = "\(PublicKey(privateKey:key))"
			logger = buildLogger
			ourKey = PublicKey(privateKey:key)
			mtu -= UInt16(IKCP_OVERHEAD)
			self.mtu = mtu
		}

		private func scheduleRepeatedKCPUpdates(context:ChannelHandlerContext) {
			updateTask = context.eventLoop.scheduleRepeatedTask(initialDelay: .seconds(0), delay: kcpUpdateTime) { [weak self, c = ContextContainer(context:context)] _ in
				guard let self = self else {
					return
				}
				let now = NIODeadline.now()
				for (key, _) in kcp {
					c.accessContext({ contextPointer in
						kcp[key]!.resendAndProbe(context: contextPointer.pointee, handler: self, now:now)
					})
				}
			}
		}
	}
}

// MARK: Basic Events
extension KCPControlBlock.Handler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		logger.debug("handler added to NIO pipeline.", metadata:["mtu_wire":"\(mtu + UInt16(IKCP_OVERHEAD))", "mtu_user":"\(mtu)"])
		context.channel.getOption(ChannelOptions.socketOption(.so_rcvbuf)).whenSuccess { [weak self, l = logger] value in
			guard let self = self else { return }
			readWindow = Int(value)
			l.trace("loaded read buffer size.", metadata: ["so_rcvbuf":"\(value)"])
		}
		context.channel.getOption(ChannelOptions.socketOption(.so_sndbuf)).whenSuccess { [weak self, l = logger] value in
			guard let self = self else { return }
			writeWindow = Int(value)
			l.trace("loaded write buffer size.", metadata: ["so_sndbuf":"\(value)"])
		}
		scheduleRepeatedKCPUpdates(context: context)
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		logger.trace("handler removed from NIO pipeline.")
	}	
}

// MARK: Read
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
		let now = NIODeadline.now()
		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: ourKey, key2: key)
			kcp[key] = KCPLivePeer(mtu: mtu, logLevel: logger.logLevel)
			kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), writeWindow: UInt32(writeWindow), readWindow: UInt32(readWindow), logLevel: logger.logLevel))
		}
		if (kcp[key]!.handleChannelRead(context: context, handler: self, associatedSegment: data, now:now) != true) {
			// handle 'Disconnected' scenario
		}
	}
}

// MARK: Write
extension KCPControlBlock.Handler {
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let data = unwrapOutboundIn(data)
		let key = data.publicKey
		// Check if control block exists
		if (kcp[key] == nil) {
			// Create the magic id control block
			let magicID = try! magicID(key1: ourKey, key2: key)
			kcp[key] = KCPLivePeer(mtu: mtu, logLevel: logger.logLevel)
			kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), writeWindow: UInt32(writeWindow), readWindow: UInt32(readWindow), logLevel: logger.logLevel))
		}

		// Send data to control block
		do {
			logger.trace("sending kcp segment", metadata: ["size": "\(data.associatedValue.readableBytes) bytes"])
			try kcp[key]!.handleWrite(context: context, handler: self, message: data.associatedValue, writePromise: promise, ackPromise:nil)
		} catch {
			logger.error("error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	func channelWritabilityChanged(context: ChannelHandlerContext) {
		defer {
			context.fireChannelWritabilityChanged()
		}
		logger.trace("kcp handler writability changed", metadata: ["isWritable":"\(context.channel.isWritable)"])
		if (context.channel.isWritable == true) {
			scheduleRepeatedKCPUpdates(context: context)
		} else {
			updateTask = nil // cancellation happens automatically via didSet block on the stored property
		}
	}
}

// MARK: User Events
extension KCPControlBlock.Handler {
	// Inbound events (Handshake Reset)
	internal func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as WireguardHandler.WireguardHandshakeNotification:
				logger.debug("resetting kcp", metadata: ["public-key_remote":"\(evt.publicKey)"])
				// Need to figure out how to make this into a conversation id
				let key = evt.publicKey
				let convID = evt.geometry.initiator.RAW_native()
				 Check if control block exists
				if (kcp[key] == nil) {
					// Create the magic id control block
					let magicID = try! magicID(key1: ourKey, key2: key)
					kcp[key] = KCPLivePeer(mtu: mtu, logLevel: logger.logLevel)
					kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: magicID, mtu: UInt32(mtu), writeWindow: UInt32(writeWindow), readWindow: UInt32(readWindow), logLevel: logger.logLevel))
				}
				kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: convID, mtu: UInt32(mtu), writeWindow: UInt32(writeWindow), readWindow: UInt32(readWindow), logLevel: logger.logLevel))

			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}

// Control Block Helper Functions
extension KCPControlBlock.Handler {
	private func magicID(key1:PublicKey, key2:PublicKey) throws -> UInt32 {
		if(key1 < key2) {
			var hasher = try WGHasher<MagicID>()
			try hasher.update(key1)
			try hasher.update(key2)
			let h = try hasher.finish()
			return h.RAW_native()
		} else {
			var hasher = try WGHasher<MagicID>()
			try hasher.update(key2)
			try hasher.update(key1)
			let h = try hasher.finish()
			return h.RAW_native()
		}
	}
}
