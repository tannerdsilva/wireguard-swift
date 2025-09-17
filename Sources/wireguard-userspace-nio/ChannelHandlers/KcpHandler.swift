import NIO
import RAW
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

enum KCPError: Error {
	/// The connection has been declared dead (max retransmits hit).
	case deadLink
}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
fileprivate struct EncodedUInt64:Sendable {}

fileprivate class KCPBlocks: @unchecked Sendable {
	let key:PublicKey
	// newest at index 0
	var controlBlocks:[ikcp_cb<EventLoopPromise<Void>>] = []
	var oldBlocks:[ikcp_cb<EventLoopPromise<Void>>] = []
	var oldBlockDeadlines:[NIODeadline] = []
	var updateTask:RepeatedTask?
	let kcpUpdateTime: TimeAmount = .milliseconds(30)
	
	// Deadline for removing the kcp if it's the last one
	var deadline:NIODeadline?
	
	// Promise variables (per promise). Index 0 is the ACTIVE promise.
	// ACTIVE promise MUST be fulfilled before any other promise for this cb.
	private var tempLen = 0
	private var pendingPromiseSndNxt:[Int] = []
	private var pendingPromisesSegCounts:[Int] = []
	private var pendingPromises:[EventLoopPromise<Void>] = []
	
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
			controlBlocks.insert(newcb, at: 0)
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
		for i in 0..<oldBlocks.count {
			do {
				try oldBlocks[i].input(data, count: data.count)
			} catch {
				continue
			}
		}
		// Control block deletion logic
		for i in 0..<oldBlocks.count {
			if(NIODeadline.now() >= oldBlockDeadlines[i]) {
				oldBlocks.remove(at: i)
				oldBlockDeadlines.remove(at: i)
				logger.info("Removed old cb. Old cb count: \(oldBlocks.count)")
			}
		}
		
		// Check acks for promises
		if(pendingPromises.count != 0) {
			if(controlBlocks[controlBlocks.count-1].snd_una >= pendingPromisesSegCounts[0] + pendingPromiseSndNxt[0]) {
				// Fulfill the promise
				pendingPromises[0].succeed()
				pendingPromises.removeFirst()
			}
		}
	}
	
	func flush(context:ContextContainer) {
		var i = 0
		while i < controlBlocks.count {
			let cb = controlBlocks[i]

			let remove = controlBlocks[i].flush(current: iclock()) { buffer, promise in
				let rawPointer = UnsafeRawBufferPointer(buffer)
				let byteBuffer = ByteBuffer(bytes: rawPointer)
				logger.trace("Sending kcp segment", metadata: ["size": "\(buffer.count) bytes"])

				context.accessContext { ctxPtr in
					ctxPtr.pointee.writeAndFlush(
						wrapOut((key, byteBuffer)),
						promise: promise
					)
				}
			}

			if controlBlocks.last?.dead_link == 1 {
				if !pendingPromises.isEmpty {
					pendingPromises[0].fail(KCPError.deadLink)
				}
			}

			if remove {
				if i == 0 {
					// Keep the block, just continue.
					i += 1
					continue
				}
				if i == controlBlocks.count - 1 {   // last block
					if !pendingPromises.isEmpty {
						pendingPromisesSegCounts[0] -=
							Int(controlBlocks[0].snd_una) - pendingPromiseSndNxt[0]
						pendingPromiseSndNxt[0] = 0
					}
				}

				oldBlocks.append(controlBlocks.remove(at: i))
				oldBlockDeadlines.append(.now() + .seconds(100))
				logger.info("Moved control block to old control blocks")
				continue
			}
			if NIODeadline.now() >= deadline! {
				controlBlocks.remove(at: i)
				updateTask?.cancel()
				logger.info("Removed last cb due to timeout")
				continue
			}
			i += 1
		}
	}
	
	func send(data:inout [UInt8], promise: EventLoopPromise<Void>?) throws {
		_ = try controlBlocks[0].send(&data, count:data.count, assosiatedData: nil)
		if let promise = promise {
			// Read and store len
			let len = data.RAW_access {
				return EncodedUInt32(RAW_staticbuff:$0.baseAddress!.advanced(by: data.count-4)).RAW_native()
			}
			tempLen = Int(len)
			pendingPromises.append(promise)
			pendingPromiseSndNxt.append(Int(controlBlocks[controlBlocks.count-1].snd_nxt))
			pendingPromisesSegCounts.append(0)
		}
		if tempLen != 0 {
			tempLen -= 1
			var count:Int
			if data.count <= Int(controlBlocks[0].mss) {
				count = 1
			} else {
				count = (data.count + Int(controlBlocks[0].mss) - 1) / Int(controlBlocks[0].mss)
			}
			pendingPromisesSegCounts[pendingPromisesSegCounts.count-1] += count
		}
		
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
			
	private var pendingMessages:[PublicKey:[(data: [UInt8], promise: EventLoopPromise<Void>?)]] = [:]
	private var pendingIncoming:[PublicKey:[ByteBuffer]] = [:]
	
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
			pendingIncoming[key, default: []].append(data)
			return
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
			_ = context.writeAndFlush(wrapOutboundOut((key, ByteBuffer(repeating: 0, count: 24))))
			pendingMessages[key, default: []].append((data, promise))
			return
		}
		do {
			try kcp[key]!.send(data:&data, promise: promise)
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
				}
				kcp[key]!.makeIkcpCb(context: context, id: evt.geometry.initiator.RAW_native())
				for var msg in pendingMessages[key] ?? [] {
					do {
						try kcp[key]!.send(data:&msg.data, promise: msg.promise)
					} catch {
						logger.error("Error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
					}
				}
				pendingMessages[key] = nil
				for msg in pendingIncoming[key] ?? [] {
					let bytes: [UInt8] = msg.getBytes(at: msg.readerIndex, length: msg.readableBytes)!
					do {
						logger.trace("Received kcp segment", metadata: ["size": "\(bytes.count) bytes"])
						try kcp[key]!.input(data:bytes)
					} catch let error {
						logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
					}
				}
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}
