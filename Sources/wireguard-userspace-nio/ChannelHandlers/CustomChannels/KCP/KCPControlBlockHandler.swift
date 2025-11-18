import NIO
import RAW
import RAW_dh25519
import RAW_blake2
import Logging
import wireguard_crypto_core

internal final class KCPLivePeer {
	/// the rolling set of control blocks associated with this peer. index 0 is the newest control block. Index count-1 reserved for the magic ID control block
	internal var controlBlocks:[KCPControlBlock] = []
	
	private let logger:Logger
	private let mtu:MTULimits
	
	// Congestion Window variables
	private let minCongestionWindow:Int
	private var congestionWindow:Int
	private var maxCongestionWindow:Int
	
	init(mtu:MTULimits, logLevel:Logger.Level, maxCongestionWindow:Int) {
		var buildLogger = Logger(label:"\(String(describing:KCPControlBlock.self)).\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		self.mtu = mtu
		self.maxCongestionWindow = maxCongestionWindow
		self.minCongestionWindow = Int(mtu.mtuOutboundOut)
		self.congestionWindow = Int(mtu.mtuOutboundOut)
	}
	
	internal var count:Int {
		get {
			return controlBlocks.count
		}
	}

	internal func insertLatestControlBlock(_ block:KCPControlBlock, context:ChannelHandlerContext, handler: KCPControlBlock.Handler) {
		controlBlocks.insert(block, at:0)
		if(count == 1) {
			controlBlocks[0].isActiveReceiver = true
		}
		for i in 0..<count {
			if(controlBlocks[i].isActiveReceiver) {
				controlBlocks[i].isStalling = true
				logger.debug("Inserting new control block", metadata: ["activeConvID": "\(controlBlocks[i].conv)"])
			}
		}
		rotateActiveControlBlock(context: context, handler: handler)
	}

	internal func handleWrite(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, message: ByteBuffer, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?, writeCounter:inout Int, isGenesis:Bool) throws {
		let now = NIODeadline.now()
		controlBlocks[0].handleWrite(context: context, handler: handler, message: message, writePromise: writePromise, ackPromise: ackPromise, isGenesis: isGenesis)
		controlBlocks[0].resendAndProbe(context: context, handler: handler, now:now, congestionWindow: &congestionWindow, minCongestionWindow: minCongestionWindow, writerCount: &writeCounter)
	}

	internal func handleChannelRead(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, associatedSegment:PeerAssociated<KCPSegment>, writeCounter:inout Int) {
		guard controlBlocks.count > 0 else {
			return
		}
		let now = NIODeadline.now()
		var receivedData:Bool = false
		cbLoop: for i in 0..<count {
			do {
				guard associatedSegment.associatedValue.header.conversationID == controlBlocks[i].conv else {
					continue cbLoop
				}
				if (try controlBlocks[i].handleChannelRead(context: context, handler: handler, associatedSegment: associatedSegment, now:now, congestionWindow: &congestionWindow, maxCongestionWindow: &maxCongestionWindow, writeCounter:&writeCounter)) {
					reset(KCPControlBlock(context: context, peerPublicKey: controlBlocks[i].peerPublicKey, conv: 0, mss:handler.mtu.mtuOutboundIn, writeWindow: UInt32(handler.writeWindow), readWindow: UInt32(handler.readWindow), logLevel: logger.logLevel))
					try controlBlocks[1].handleChannelRead(context: context, handler: handler, associatedSegment: associatedSegment, now:now, congestionWindow: &congestionWindow, maxCongestionWindow: &maxCongestionWindow, writeCounter:&writeCounter)
					return
				}
				if(congestionWindow > maxCongestionWindow) {
					congestionWindow = maxCongestionWindow
				}
				receivedData = true
				break cbLoop
			} catch {
				continue
			}
		}
		// Segment did not belong in any of the control blocks
		if(receivedData == false) {
			if(associatedSegment.associatedValue.header.command == .probeRequest) {
				reprobe(context: context, handler: handler, associatedSegment: associatedSegment)
			} else if (associatedSegment.associatedValue.header.command == .genesis) {
				do {
					reset(KCPControlBlock(context: context, peerPublicKey: controlBlocks[0].peerPublicKey, conv: 0, mss:handler.mtu.mtuOutboundIn, writeWindow: UInt32(handler.writeWindow), readWindow: UInt32(handler.readWindow), logLevel: logger.logLevel))
					try controlBlocks[1].handleChannelRead(context: context, handler: handler, associatedSegment: associatedSegment, now:now, congestionWindow: &congestionWindow, maxCongestionWindow: &maxCongestionWindow, writeCounter:&writeCounter)
				} catch { }
			}
		} else {
			rotateActiveControlBlock(context: context, handler: handler)
		}
	}

	internal func resendAndProbe(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, writeCounter:inout Int) {
		let now = NIODeadline.now()
		for i in  0..<count {
			controlBlocks[i].resendAndProbe(context: context, handler: handler, now:now, congestionWindow: &congestionWindow, minCongestionWindow: minCongestionWindow, writerCount: &writeCounter)
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
				controlBlocks.remove(at: i)
				return
			}
		}
	}
	
	internal func reset(_ block:KCPControlBlock) {
		controlBlocks = [controlBlocks[0]]
		controlBlocks.append(block)
		controlBlocks[0].isActiveReceiver = false
		controlBlocks[1].isActiveReceiver = true
		logger.info("Connection reset. Recreating kcp control blocks.")
	}
	
	internal func reprobe(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, associatedSegment:PeerAssociated<KCPSegment>) {
		context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:controlBlocks[0].peerPublicKey, associatedValue:KCPSegment(header:KCPSegment.Header(conv:associatedSegment.associatedValue.header.conversationID, cmd:.probeKill, rcv_wnd_size:0, frg:0, sn:0, ts:0, una:0, len:0), data:ByteBufferView()))), promise:nil)
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

		let mtu:MTULimits
		var count = 0

		internal var readWindow:Int!
		internal var writeWindow:Int!

		private var writesSinceLastFlush:Int = 0
		private var writesSinceChannelReadComplete:Int = 0
			
		internal init(key:MemoryGuarded<PrivateKey>, mtu:inout MTULimits, logLevel:Logger.Level) {
			var buildLogger = Logger(label:"\(String(describing:KCPControlBlock.self)).\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			buildLogger[metadataKey:"public-key_self"] = "\(PublicKey(privateKey:key))"
			logger = buildLogger
			ourKey = PublicKey(privateKey:key)
			mtu = MTULimits(mtuInboundIn:mtu.mtuInboundIn, mtuOutboundOut:mtu.mtuOutboundOut, mtuOutboundIn:mtu.mtuOutboundOut - MemoryLayout<KCPSegment.Header>.size, mtuInboundOut:mtu.mtuInboundIn - MemoryLayout<KCPSegment.Header>.size)
			self.mtu = mtu
		}

		private func scheduleRepeatedKCPUpdates(context:ChannelHandlerContext) {
			updateTask = context.eventLoop.scheduleRepeatedTask(initialDelay: .seconds(0), delay: kcpUpdateTime) { [weak self, c = ContextContainer(context:context)] _ in
				guard let self = self else {
					return
				}
				for (key, _) in kcp {
					c.accessContext({ contextPointer in
						kcp[key]!.resendAndProbe(context: contextPointer.pointee, handler: self, writeCounter: &writesSinceLastFlush)
					})
				}
			}
		}
	}
}

// MARK: Basic Events
extension KCPControlBlock.Handler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		logger.debug("handler added to pipeline.", metadata:["mtu_outboundOut":"\(mtu.mtuOutboundOut)", "mtu_outboundIn":"\(mtu.mtuOutboundIn)", "mtu_inboundIn":"\(mtu.mtuInboundIn)", "mtu_inboundOut":"\(mtu.mtuInboundOut)"])
		context.channel.getOption(ChannelOptions.socketOption(.so_rcvbuf)).whenSuccess { [weak self, l = logger] value in
			guard let self = self else { return }
			readWindow = Int(value)
			l.notice("loaded read buffer size.", metadata: ["so_rcvbuf":"\(value)"])
		}
		context.channel.getOption(ChannelOptions.socketOption(.so_sndbuf)).whenSuccess { [weak self, l = logger] value in
			guard let self = self else { return }
			writeWindow = Int(value)
			l.notice("loaded write buffer size.", metadata: ["so_sndbuf":"\(value)"])
		}
		scheduleRepeatedKCPUpdates(context: context)
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		updateTask?.cancel()
		updateTask = nil
		logger.trace("handler removed from NIO pipeline.")
	}	
}

// MARK: Read
extension KCPControlBlock.Handler {
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let data = unwrapInboundIn(data)
		let key = data.publicKey
		if (kcp[key] == nil) {
			kcp[key] = KCPLivePeer(mtu:mtu, logLevel:logger.logLevel, maxCongestionWindow: writeWindow)
			kcp[key]!.insertLatestControlBlock(KCPControlBlock(context:context, peerPublicKey:key, conv:0, mss:mtu.mtuOutboundIn, writeWindow:UInt32(writeWindow), readWindow:UInt32(readWindow), logLevel:logger.logLevel), context: context, handler: self)
		}
		kcp[key]!.handleChannelRead(context: context, handler: self, associatedSegment: data, writeCounter:&writesSinceLastFlush)
	}
}

// MARK: Write
extension KCPControlBlock.Handler {
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let data = unwrapOutboundIn(data)
		let key = data.publicKey
		// Check if control block exists
		var isGenesis = false
		if (kcp[key] == nil) {
			// Create the magic id control block
			kcp[key] = KCPLivePeer(mtu:mtu, logLevel: logger.logLevel, maxCongestionWindow: writeWindow)
			kcp[key]!.insertLatestControlBlock(KCPControlBlock(context: context, peerPublicKey: key, conv: 0, mss:mtu.mtuOutboundIn, writeWindow: UInt32(writeWindow), readWindow: UInt32(readWindow), logLevel: logger.logLevel), context: context, handler: self)
			isGenesis = true
		}

		// Send data to control block
		var iterationAdded = 0
		do {
			logger.trace("sending kcp segment", metadata: ["size": "\(data.associatedValue.readableBytes) bytes"])
			try kcp[key]!.handleWrite(context: context, handler:self, message: data.associatedValue, writePromise: promise, ackPromise:nil, writeCounter:&iterationAdded, isGenesis: isGenesis)
		} catch {
			logger.error("error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
		writesSinceLastFlush += iterationAdded
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
	func flush(context:ChannelHandlerContext) {
		if writesSinceLastFlush > 0 {
			logger.trace("flushing kcp handler", metadata: ["writes_since_last_flush":"\(writesSinceLastFlush)"])
			writesSinceLastFlush = 0
			writesSinceChannelReadComplete = 0
			context.flush()
		} else {
			logger.trace("flush called with no writes since last flush")
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
				let convID = UInt16(truncatingIfNeeded: evt.geometry.initiator.RAW_native())
				 // Check if control block exists
				 if (kcp[key] == nil) {
				 	// Create the magic id control block
				 	kcp[key] = KCPLivePeer(mtu: mtu, logLevel: logger.logLevel, maxCongestionWindow: writeWindow)
					 kcp[key]!.insertLatestControlBlock(KCPControlBlock(context:context, peerPublicKey:key, conv:0, mss:mtu.mtuOutboundIn, writeWindow:UInt32(writeWindow), readWindow:UInt32(readWindow), logLevel:logger.logLevel), context: context, handler: self)
				 }
				kcp[key]!.insertLatestControlBlock(KCPControlBlock(context:context, peerPublicKey:key, conv:convID, mss:mtu.mtuOutboundIn, writeWindow:UInt32(writeWindow), readWindow:UInt32(readWindow), logLevel:logger.logLevel), context: context, handler: self)

			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}
