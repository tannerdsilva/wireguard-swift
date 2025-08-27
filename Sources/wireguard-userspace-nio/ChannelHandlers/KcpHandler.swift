import NIO
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = WireguardEvent
	public typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = InterfaceInstruction
	
	private var kcp:[PublicKey:ikcp_cb<EventLoopPromise<Void>>] = [:]
	
	private var kcp_peers = [PeerIndex:Void]()
	
	private let logger:Logger
	
	// task for updating for acks
	private var kcpUpdateTasks: [PublicKey: RepeatedTask] = [:]
	private var kcpStartTimers: [PublicKey: UInt32] = [:]
	private let kcpUpdateTime: TimeAmount = .milliseconds(100)

	// task for killing ikcp when inactive
	private var kcpKillTasks:[PublicKey:Scheduled<Void>] = [:]
	private let kcpKillTime:TimeAmount = .seconds(300)
	
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

	private func makeIkcpCb(key:PublicKey, context:ChannelHandlerContext) {
		kcp[key] = ikcp_cb<EventLoopPromise<Void>>(conv: 0)
		kcp[key]!.setNoDelay(1, interval:100, resend:5, nc:1)
	}

	private func kcpUpdates(for key:PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[key] == nil else { return }
		kcpStartTimers[key] = 0
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			self.kcp[key]!.update(current:iclock()) { buffer, promise in
				let bytes = Array(UnsafeBufferPointer(start: buffer.baseAddress, count: buffer.count))
				c.accessContext { contextPointer in
					contextPointer.pointee.write(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, bytes)), promise:promise)
				}
			 }

			rcvLoop: while true {
				do {
					let receivedData = try self.kcp[key]!.receive()
					c.accessContext { contextPointer in
						contextPointer.pointee.fireChannelRead(wrapInboundOut((key, receivedData)))
					}
				} catch { break rcvLoop } // received no data or it failed
			}
		}
		kcpUpdateTasks[key] = task
	}
	
	private func reset(key:PublicKey, context:ChannelHandlerContext) {
		if (kcpKillTasks[key] == nil) {
			kcpKillTasks[key] = context.eventLoop.scheduleTask(in:kcpKillTime) { [weak self] in
				self!.kcp[key] = nil
			}
		} else {
			kcpKillTasks[key]!.cancel()
			kcpKillTasks[key] = context.eventLoop.scheduleTask(in:kcpKillTime) { [weak self] in
				self!.kcp[key] = nil
			}
		}
	}
	
	// Receiving kcp segment
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		switch unwrapInboundIn(data) {
			case .transitData(let key, let peerIndex, let data):
				if (kcp[key] == nil) {
					makeIkcpCb(key:key, context:context)
					kcpUpdates(for:key, context:context)
				}
				do {
					_ = try kcp[key]!.input(data, count: data.count)
				} catch let error {
					logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
				}
			case .handshakeCompleted(let pubkey, let peerIndex, let geometry):
				logger.debug("configuring for handshake", metadata:["peer_index":"\(peerIndex)", "peer_public_key":"\(pubkey)"])
				kcp_peers[peerIndex] = ()
		}
	}
	
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
			kcpUpdates(for: key, context: context)
		}

		do {
			_ = try kcp[key]!.send(&data, count:data.count, assosiatedData: promise)
		} catch let error {
			logger.error("error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
}
