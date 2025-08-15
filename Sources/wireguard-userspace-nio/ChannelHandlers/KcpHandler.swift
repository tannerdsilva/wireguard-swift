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
	
	private var logger:Logger
	
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

	internal func handlerAdded(context: ChannelHandlerContext) {
		logger.trace("handler added to pipeline.")
	}

	private func makeIkcpCb(key:PublicKey, context:ChannelHandlerContext) {
		kcp[key] = ikcp_cb(conv: 0, user: nil, synchronous: true)
	}
	
	private func kcpCheckAck(for key:PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[key] == nil else { return }
		kcpStartTimers[key] = 0
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context: context)] _ in
			guard let self = self else { return }
			
			if(!kcp[key]!.ackUpToDate()) {
				kcpStartTimers[key]! += 10_000
				kcp[key]!.update(current: kcpStartTimers[key]!, output: { buffer in
					// Pass outbound kcp segment buffers to data handler
					c.accessContext { contextPointer in
						contextPointer.pointee.writeAndFlush(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, buffer)) , promise: nil)
					}
				})
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
		
		_ = kcp[key]!.input(data: data)
		var i = 0
		var len = 0
		while let receivedData = try? kcp[key]!.receive() {
			defer {
				i += 1
				len += receivedData.count
			}
			context.fireChannelRead(wrapInboundOut((key, receivedData)))
		}
		if i > 0 {
			logger.trace("fired kcp segments down pipeline", metadata:["segment_count":"\(i)", "total_bytes":"\(len)"])
		}
		
		kcp[key]!.update(current:0, output: { buffer in
			// Pass outbound kcp segment buffers to data handler
			context.writeAndFlush(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, buffer)) , promise: nil)
		})
	}
	
	// Receiving data which needs to be sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
		}
		
		var _ = kcp[key]!.send(buffer:&data, _len:data.count)
		
		kcp[key]!.update(current:0, output: { buffer in
			// Pass outbound kcp segment buffers to data handler
			context.writeAndFlush(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, buffer)) , promise:promise)
		})
		
		kcpCheckAck(for: key, context: context)
	}
}
