import NIO
import RAW_dh25519
import kcp_swift
import Logging

internal final class KCPHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, [UInt8])
	public typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = InterfaceInstruction
	
	private var kcp:[PublicKey: ikcp_cb] = [:]
	
	private let logger:Logger
	
	private var kcpUpdateTasks: [PublicKey: RepeatedTask] = [:]
	private var kcpStartTimers: [PublicKey: UInt32] = [:]
	private let kcpUpdateTime: TimeAmount = .milliseconds(100)

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}
	
	private func makeIkcpCb(key:PublicKey, context:ChannelHandlerContext) {
		kcp[key] = ikcp_cb(conv: 0, output: { buffer in
			// Pass outbound kcp segment buffers to data handler
			context.writeAndFlush(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, buffer)) , promise: nil)
		 }, user: nil)
	}
	
	private func kcpUpdates(for key:PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[key] == nil else { return }
		kcpStartTimers[key] = 0
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			self.kcp[key]!.update(current: kcpStartTimers[key]!)
			
			do {
				if let receivedData = try self.kcp[key]!.receive() {
					c.accessContext { contextPointer in
						contextPointer.pointee.fireChannelRead(wrapInboundOut((key, receivedData)))
					}
				}
			} catch { } // received no data or it failed

			kcpStartTimers[key]! += 10_000
		}
		
		kcpUpdateTasks[key] = task
	}
	
	// Receiving kcp segment
	internal func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let (key, data) = unwrapInboundIn(data)
		if(kcp[key] == nil) {
			makeIkcpCb(key: key, context: context)
			kcpUpdates(for: key, context: context)
		}
		
		var _ = kcp[key]!.input(data: data)
	}
	
	// Receiving data which needs to be sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if(kcp[key] == nil) {
			makeIkcpCb(key: key, context: context)
			kcpUpdates(for: key, context: context)
		}
		
		while(data != []) {
			if(data.count >= 150_000) {
				var _ = kcp[key]!.send(buffer: &data, _len: 150_000)
			} else {
				var _ = kcp[key]!.send(buffer: &data, _len: data.count)
			}
		}
		logger.debug("Sending outbound kcp segment to data handler")
	}
}
