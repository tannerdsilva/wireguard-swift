import NIO
import RAW_dh25519
import kcp_swift
import Logging

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, [UInt8])
	public typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = InterfaceInstruction
	
	private var kcp:[PublicKey: ikcp_cb<EventLoopPromise<Void>>] = [:]
	
	private var logger:Logger
	
	// Task for updating for acks
	private var kcpUpdateTasks: [PublicKey: RepeatedTask] = [:]
	private var kcpStartTimers: [PublicKey: UInt32] = [:]
	private let kcpUpdateTime: TimeAmount = .milliseconds(10)
	
	// Tasks for killing ikcp when inactive
	private var kcpKillTasks: [PublicKey: Scheduled<Void>] = [:]
	private let kcpKillTime: TimeAmount = .seconds(300)
	
	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}

	internal func handlerAdded(context: ChannelHandlerContext) {
		logger.trace("handler added to pipeline.")
	}

	private func makeIkcpCb(key:PublicKey, context:ChannelHandlerContext) {
		kcp[key] = ikcp_cb<EventLoopPromise<Void>>(conv: 0, output: { [weak self] buffer, promise in
			guard let self = self else { return }
			// Pass outbound kcp segment buffers to data handler
			let bytes = Array(UnsafeBufferPointer(start: buffer.baseAddress, count: buffer.count))
			context.writeAndFlush(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, bytes)) , promise: promise)
		 })
        kcp[key]!.setNoDelay(1,interval: 10,resend: 2,nc: 1)
	}
	
	private func kcpUpdates(for key:PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[key] == nil else { return }
		kcpStartTimers[key] = 0
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			self.kcp[key]!.update(current: kcpStartTimers[key]!)

			do {
				let receivedData = try self.kcp[key]!.receive()
				c.accessContext { contextPointer in
					contextPointer.pointee.fireChannelRead(wrapInboundOut((key, receivedData)))
				}
			} catch { } // received no data or it failed

			kcpStartTimers[key]! += 10
		}
		
		kcpUpdateTasks[key] = task
	}
	
	private func reset(key:PublicKey, context:ChannelHandlerContext) {
		if(kcpKillTasks[key] == nil) {
			kcpKillTasks[key] = context.eventLoop.scheduleTask(in: kcpKillTime) { [weak self] in
				self!.kcp[key] = nil
			}
		} else {
			kcpKillTasks[key]!.cancel()
			kcpKillTasks[key] = context.eventLoop.scheduleTask(in: kcpKillTime) { [weak self] in
				self!.kcp[key] = nil
			}
		}
	}
	
	// Receiving kcp segment
	internal func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let (key, data) = unwrapInboundIn(data)
		if(kcp[key] == nil) {
			makeIkcpCb(key: key, context: context)
			kcpUpdates(for: key, context: context)
		}
		
		do {
			_ = try kcp[key]!.input(data, count: data.count)
		} catch let error {
			logger.error("Error parsing kcp data: \(error)")
		}
	}
	
	// Receiving data which needs to be sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
			kcpUpdates(for: key, context: context)
		}
		
		do {
			_ = try kcp[key]!.send(&data, count:data.count, assosiatedData: promise)
		} catch let error {
			logger.error("Error sending kcp data: \(error)")
		}
	}
}
