import NIO
import RAW_dh25519
import kcp_swift
import Logging

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, [UInt8])
	public typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = InterfaceInstruction
	
	private var kcp:[PublicKey:ikcp_cb<EventLoopPromise<Void>>] = [:]
	
	private var logger:Logger
	private let eventRefreshTimeInterval:TimeAmount = .milliseconds(10)
	
	// Task for updating for acks
	private var kcpUpdateTasks:[PublicKey: RepeatedTask] = [:]
	private var kcpStartTimers:[PublicKey: UInt32] = [:]
	
	// Tasks for killing ikcp when inactive
	private var kcpKillTasks:[PublicKey:Scheduled<Void>] = [:]
	private let kcpKillTime:TimeAmount = .seconds(300)
	
	private var scheduledRepeatedTask:RepeatedTask? = nil
	
	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}

	internal func handlerAdded(context: ChannelHandlerContext) {
		logger.trace("handler added to pipeline.")
	}

	private func makeIkcpCb(key:PublicKey, context:ChannelHandlerContext) {
		kcp[key] = ikcp_cb<EventLoopPromise<Void>>(conv: 0)
		kcp[key]!.setNoDelay(1, interval:20, resend:1, nc:1)
	}
	
	private func updateControlBlock(now: UInt32, publicKey: PublicKey, context: ChannelHandlerContext) {
		kcp[publicKey]!.update(current: now) { buffer, promise in
			let bytes = Array(UnsafeBufferPointer(start: buffer.baseAddress, count: buffer.count))
			context.write(wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(publicKey, bytes)), promise: promise)
		}
	}
	
	private func updateAllControlBlocks(context:ChannelHandlerContext) {
		let now = iclock()
		mainLoop: for (pk, _) in kcp {
			updateControlBlock(now:now, publicKey:pk, context:context)
			rcvLoop: while true {
				do {
					let bytes = try kcp[pk]!.receive()
					context.fireChannelRead(wrapInboundOut((pk, bytes)))
				} catch { break rcvLoop }
			}
		}
		context.flush()
	}
	
	private func scheduledTaskFire(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		updateAllControlBlocks(context:context)
	}
	
	private func startPeriodicUpdate(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		guard scheduledRepeatedTask == nil else {
			return
		}
		scheduledRepeatedTask = context.eventLoop.scheduleRepeatedTask(initialDelay: eventRefreshTimeInterval, delay: eventRefreshTimeInterval, { [weak self, c = ContextContainer(context:context), l = logger] _ in
			guard let self = self else { return }
			let now = iclock()
			c.accessContext { ctxPtr in
				self.scheduledTaskFire(context:ctxPtr.pointee)
			}
		})
	}
	
//	private func scheduleNextUpdate(context:ChannelHandlerContext) {
//		#if DEBUG
//		context.eventLoop.assertInEventLoop()
//		#endif
//		var logger = logger
//		logger[metadataKey:"_func"] = "\(#function)"
//		logger.trace("scheduling next update event.")
//		let now = iclock()
//		var minimumCheck:UInt32? = nil
//		for curPubKey in kcp.keys {
//			let checkVal = kcp[curPubKey]!.check(current:now)
//			logger.trace("public key wants a scheduled event at '\(checkVal)'", metadata:["public_key":"\(curPubKey)"])
//			switch minimumCheck {
//				case .some(let val):
//					if val > checkVal {
//						minimumCheck = checkVal
//					}
//				case .none:
//					minimumCheck = checkVal
//			}
//		}
//		let delay:UInt32
//		if minimumCheck == nil {
//			delay = 0
//			minimumCheck = 0
//		} else {
//			delay = minimumCheck! &- now
//		}
//		if scheduledTaskTimer != nil {
//			return
//			guard scheduledTaskTimer!.0 != minimumCheck else {
//				logger.trace("the timer is already scheduled at this time.")
//				return
//			}
//			scheduledTaskTimer!.1.cancel()
//		}
//		logger.debug("scheduling next future kcp update event.", metadata:["next_ms":"\(delay)"])
//		let storeScheduledTask = context.eventLoop.scheduleTask(in:.milliseconds(Int64(delay)), { [weak self, c = ContextContainer(context:context), l = logger] in
//			guard let self = self else { return }
//			l.debug("scheduled kcp task fire")
//			c.accessContext { ctxPtr in
//				self.scheduledTaskFire(context:ctxPtr.pointee)
//				self.scheduleNextUpdate(context:ctxPtr.pointee)
//			}
//		})
//		scheduledTaskTimer = (minimumCheck!, storeScheduledTask)
//	}
		
	// Receiving kcp segment
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let now = iclock()
		defer {
			startPeriodicUpdate(context:context)
		}
		let (key, data) = unwrapInboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key: key, context: context)
		}
		do {
			_ = try kcp[key]!.input(data, count: data.count)
			updateControlBlock(now:now, publicKey:key, context:context)
			do {
				while true {
					let bytes = try kcp[key]!.receive()
					context.fireChannelRead(wrapInboundOut((key, bytes)))
				}
			} catch {}
		} catch let error {
			logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let now = iclock()
		defer {
			startPeriodicUpdate(context:context)
		}
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
		}
		
		do {
			_ = try kcp[key]!.send(&data, count:data.count, assosiatedData: promise)
			updateControlBlock(now:now, publicKey:key, context:context)
			do {
				while true {
					let bytes = try kcp[key]!.receive()
					context.fireChannelRead(wrapInboundOut((key, bytes)))
				}
			} catch {}
		} catch let error {
			logger.error("error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	
	func flush(context: ChannelHandlerContext) {
		context.flush()
	}
}
