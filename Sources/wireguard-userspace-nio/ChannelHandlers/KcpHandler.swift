import NIO
import RAW
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
fileprivate struct EncodedUInt64:Sendable {}

fileprivate class KCPBlocks: @unchecked Sendable {
	let key:PublicKey
	// newest at index 0
	var controlBlocks:[ikcp_cb<EventLoopPromise<Void>>] = []
	var updateTask:RepeatedTask?
	let kcpUpdateTime: TimeAmount = .milliseconds(30)
	
	// Deadline for removing the kcp if it's the last one
	var deadline:NIODeadline?
	
	// All pending messages (akin to kcp send queue)
	private var pendingPackets:[LinkedList<[UInt8]>] = []
	
	private let wrapOut: ((PublicKey, ByteBuffer)) -> NIOAny
	private let wrapIn: ((PublicKey, [UInt8])) -> NIOAny
	
	private let logger:Logger
	
	internal init(key:PublicKey, context: ChannelHandlerContext, wrapOut: @escaping ((PublicKey, ByteBuffer)) -> NIOAny, wrapIn: @escaping ((PublicKey, [UInt8])) -> NIOAny, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		
		self.key = key
		self.wrapOut = wrapOut
		self.wrapIn = wrapIn
		makeIkcpCb(context: context)
	}
	
	func makeIkcpCb(context: ChannelHandlerContext, id: UInt32 = 0) -> Void {
		// Create a new cb with a unique conv id
		var newcb = ikcp_cb<EventLoopPromise<Void>>(conv: id)
		// Assign kcp variables
		newcb.rx_maxrto = 10_000
		
		if(controlBlocks.isEmpty) {
			// There are no cb's, so don't copy rtt vals
			controlBlocks.append(newcb)
		} else {
			// There are cb's, copy the rtt vals of the oldest one
			let oldcb = controlBlocks[controlBlocks.count-1]
			newcb.rx_rttval = oldcb.rx_rttval
			newcb.rx_srtt = oldcb.rx_srtt
			newcb.rx_rto = oldcb.rx_rto
			controlBlocks.append(newcb)
		}
		
		kcpUpdates(context: context)
		
		// Reset the deadline
		deadline = .now() + .seconds(300)
	}
	
	func input(data: [UInt8]) throws {
		for i in 0..<controlBlocks.count {
			do {
				try controlBlocks[i].input(data, count: data.count)
			} catch {
				continue
			}
		}
	}
	
	func flush(context:ContextContainer) {
		for i in 0..<controlBlocks.count {
			let remove = controlBlocks[i].flush(current:iclock()) { buffer, promise in
				let rawPointer = UnsafeRawBufferPointer(buffer)
				let byteBuffer = ByteBuffer(bytes: rawPointer)
				logger.trace("Sending kcp segment", metadata: ["size": "\(buffer.count) bytes"])
				context.accessContext { contextPointer in
					contextPointer.pointee.writeAndFlush(wrapOut((key, byteBuffer)), promise:promise)
				}
			 }
			if(remove && i != 0) {
				// Removes the cb if it's inactive and old
				controlBlocks.remove(at: i)
				logger.info("Removed old cb. Cb count: \(controlBlocks.count)")
			} else if (remove && NIODeadline.now() >= deadline!) {
				controlBlocks.remove(at: i)
				updateTask!.cancel()
				logger.info("Removed last cb due to timout")
			}
		}
	}
	
	func send(data:inout [UInt8]) throws {
		_ = try controlBlocks[0].send(&data, count:data.count, assosiatedData: nil)
	}
	
	private func kcpUpdates(context:ChannelHandlerContext) {
		if(updateTask != nil) {
			updateTask!.cancel()
		}
		updateTask = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			flush(context: c)
			
			rcvLoop: while true {
				do {
					var mutateControlBlock = controlBlocks[controlBlocks.count-1]
					let receivedData = try mutateControlBlock.receive()
					controlBlocks[controlBlocks.count-1] = mutateControlBlock
					
					logger.debug("Compiled kcp message. Passing to splicer.", metadata: ["size": "\(receivedData.count) bytes"])
					c.accessContext { contextPointer in
						contextPointer.pointee.fireChannelRead(wrapIn((key, receivedData)))
					}
				} catch { break rcvLoop } // received no data or it failed
			}
		}
	}
}

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, ByteBuffer)
	internal typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = (PublicKey, ByteBuffer)
	
	private var kcp:[PublicKey:KCPBlocks] = [:]
			
	private let logger:Logger
		
	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}

	internal func handlerAdded(context:ChannelHandlerContext) {
		logger.trace("handler added to NIO pipeline.")
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		logger.trace("handler removed from NIO pipeline.")
	}

	
	
	// Receiving kcp segment
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let (key, data) = unwrapInboundIn(data)
		if (kcp[key] == nil) {
			kcp[key] = KCPBlocks(key: key, context: context, wrapOut: wrapOutboundOut, wrapIn: wrapInboundOut, logLevel: logger.logLevel)
		}

		let bytes: [UInt8] = data.getBytes(at: data.readerIndex, length: data.readableBytes)!
		
		do {
			logger.trace("Received kcp segment", metadata: ["size": "\(bytes.count) bytes"])
			try kcp[key]!.input(data:bytes)
		} catch let error {
			logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			kcp[key] = KCPBlocks(key: key, context: context, wrapOut: wrapOutboundOut, wrapIn: wrapInboundOut, logLevel: logger.logLevel)
		}
		do {
			try kcp[key]!.send(data:&data)
		} catch {
			logger.error("Error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	
	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as WireguardHandler.WireguardHandshakeNotification:
				logger.debug("Resetting kcp", metadata: ["public-key_remote":"\(evt.publicKey)"])
				// Need to figure out how to make this into a conversation id
				let key = evt.publicKey
				if (kcp[key] == nil) {
					kcp[key] = KCPBlocks(key: key, context: context, wrapOut: wrapOutboundOut, wrapIn: wrapInboundOut, logLevel: logger.logLevel)
				} else {
					kcp[key]!.makeIkcpCb(context: context, id: evt.peerIndex.RAW_native())
				}
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}
