import NIO
import RAW_dh25519
import kcp_swift
import Logging

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, [UInt8])
	public typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = InterfaceInstruction
	
	private var kcp:[PublicKey: ikcp_cb] = [:]
	
	private let logger:Logger
	
	// Task for updating for acks
	private var kcpUpdateTasks: [PublicKey: RepeatedTask] = [:]
	private var kcpStartTimers: [PublicKey: UInt32] = [:]
	private let kcpUpdateTime: TimeAmount = .seconds(5)
	
	// Tasks for killing ikcp when inactive
	private var kcpKillTasks: [PublicKey: Scheduled<Void>] = [:]
	private let kcpKillTime: TimeAmount = .seconds(300)

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}
	
	private func makeIkcpCb(key:PublicKey, context:ChannelHandlerContext) {
		kcp[key] = ikcp_cb(conv: 0, output: { buffer in
			// Pass outbound kcp segment buffers to data handler
			context.writeAndFlush(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, buffer)) , promise: nil)
		}, user: nil, synchronous: true)
	}
	
	private func kcpCheckAck(for key:PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[key] == nil else { return }
		kcpStartTimers[key] = 0
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self] _ in
			guard let self = self else { return }
			
			if(!kcp[key]!.ackUpToDate()) {
				kcpStartTimers[key]! += 10_000
				kcp[key]!.update(current: kcpStartTimers[key]!)
			} else {
				kcpUpdateTasks[key] = nil
			}
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
		}
		
		var _ = kcp[key]!.input(data: data)
		
		while let receivedData = try! kcp[key]!.receive() {
			context.fireChannelRead(wrapInboundOut((key, receivedData)))
		}
		
		kcp[key]!.update(current: 0)
	}
	
	// Receiving data which needs to be sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
		}
		
		var _ = kcp[key]!.send(buffer:&data, _len:data.count)
		
		kcp[key]!.update(current: 0)
		
		kcpCheckAck(for: key, context: context)
		logger.debug("Sending outbound kcp segment to data handler")
	}
}
