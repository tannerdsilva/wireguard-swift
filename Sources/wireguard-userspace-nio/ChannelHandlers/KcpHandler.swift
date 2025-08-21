import NIO
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PeerIndex, [UInt8])
	public typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = InterfaceInstruction
	
	private var kcp:[PeerIndex:ikcp_cb<EventLoopPromise<Void>>] = [:]
	private var keyToPeerIndex:[PublicKey:(previous:PeerIndex?, current:PeerIndex?, next:PeerIndex?)] = [:]
	
	// Pending incoming and outgoing packets
	private var pendingWriteFutures:[PublicKey:[(data:[UInt8], promise:EventLoopPromise<Void>?)]] = [:]
	
	private var logger:Logger
	
	// Task for updating for acks
	private var kcpUpdateTasks: [PeerIndex: RepeatedTask] = [:]
	private let kcpUpdateTime: TimeAmount = .milliseconds(10)
	
	// Tasks for killing ikcp when inactive
	private var kcpKillTasks:[PeerIndex:Scheduled<Void>] = [:]
	private let kcpKillTime:TimeAmount = .seconds(300)
	
	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}

	internal func handlerAdded(context: ChannelHandlerContext) {
		logger.trace("handler added to pipeline.")
	}

	private func makeIkcpCb(peerIndex:PeerIndex, context:ChannelHandlerContext) {
		kcp[peerIndex] = ikcp_cb<EventLoopPromise<Void>>(conv: 0)
		kcp[peerIndex]!.setNoDelay(0, interval:10, resend:0, nc:1)
	}

	private func kcpUpdates(for peerIndex:PeerIndex, key: PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[peerIndex] == nil else { return }
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			self.kcp[peerIndex]!.update(current:iclock()) { buffer, promise in
				let bytes = Array(UnsafeBufferPointer(start: buffer.baseAddress, count: buffer.count))
				c.accessContext { contextPointer in
					contextPointer.pointee.write(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, peerIndex, bytes)), promise:promise)
				}
			 }

			rcvLoop: while true {
				do {
					let receivedData = try self.kcp[peerIndex]!.receive()
					c.accessContext { contextPointer in
						contextPointer.pointee.fireChannelRead(wrapInboundOut((key, receivedData)))
					}
				} catch { break rcvLoop } // received no data or it failed
			}
		}
		kcpUpdateTasks[peerIndex] = task
	}
	
	// Receiving kcp segment
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let (key, data) = unwrapInboundIn(data)
		
		do {
			_ = try kcp[key]!.input(data, count: data.count)
		} catch let error {
			logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)

		do {
			if let sessions = keyToPeerIndex[key] {
				if let current = sessions.current {
					_ = try kcp[current]!.send(&data, count:data.count, assosiatedData: promise)
					return
				} else if let next = sessions.next {
					_ = try kcp[next]!.send(&data, count:data.count, assosiatedData: promise)
					return
				}
			}
			// Add the data to pending packets which will get sent once a handshake is established
			pendingWriteFutures[key, default: []].append((data, promise))
			// Send nil peer index so that the data handler sends a handshake initiation
			context.writeAndFlush(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, nil, [])), promise:nil)
			
		} catch let error {
			logger.error("error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	
	// Handle receiving new peer index rekey
	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as PipelineEvent:
				switch evt {
					case let .reKeyEvent(peerIndex, sessions, publicKey):
						// Add peer's kcp and add public key relation to peer
						makeIkcpCb(peerIndex:peerIndex, context:context)
						kcpUpdates(for: peerIndex, key: publicKey, context: context)
						
						keyToPeerIndex[publicKey] = sessions
						
						// Handle encrypting packets waiting on handshake completion
						guard let packets = pendingWriteFutures[publicKey] else {
							return
						}
						for packet in packets {
							var data = packet.data
							do {
								_ = try kcp[peerIndex]!.send(&data, count: data.count, assosiatedData: packet.promise)
							} catch let error {
								logger.error("error sending kcp data", metadata:["peer_public_key":"\(publicKey)", "error_thrown":"\(error)"])
							}
						}
						pendingWriteFutures[publicKey] = nil
						
					case let .peerKilled(peerIndex, sessions, publicKey):
						kcpUpdateTasks[peerIndex]!.cancel()
						kcp[peerIndex] = nil
						keyToPeerIndex[publicKey] = sessions
					case let .sessionsUpdated(sessions, publicKey):
						keyToPeerIndex[publicKey] = sessions
				}
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}
