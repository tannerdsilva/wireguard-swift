import NIO
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

internal struct Rotating<Element> {
	internal var previous:Element? = nil
	internal var current:Element? = nil
	internal var next:Element? = nil
	
	internal init(previous pIn:Element?, current cIn:Element?, next nIn:Element?) {
		previous = pIn
		current = cIn
		next = nIn
	}
}

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = WireguardEvent
	public typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = InterfaceInstruction
	
	private var kcp:[PublicKey:ikcp_cb<EventLoopPromise<Void>>] = [:]
	
	// All pending messages (akin to kcp send queue)
	private var pendingPackets:[PublicKey:LinkedList<[UInt8]>] = [:]
	private var packetIterators:[PublicKey:LinkedList<[UInt8]>.Iterator] = [:]
	private var ackCounter:Int = 0
	
	private var kcp_peers = [PeerIndex:Void]()
	
	private let logger:Logger
	
	// task for updating for acks
	private var kcpUpdateTasks: [PublicKey: RepeatedTask] = [:]
	private var kcpStartTimers: [PublicKey: UInt32] = [:]
	private let kcpUpdateTime: TimeAmount = .milliseconds(30)

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
		kcp[key]!.setNoDelay(0, interval:30)
		kcp[key]!.rx_rto = 60000
		kcp[key]!.rx_minrto = 60000
		kcp[key]!.rx_maxrto = 60000
	}

	private func kcpUpdates(for key:PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[key] == nil else { return }
		kcpStartTimers[key] = 0
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			self.kcp[key]!.flush(current:iclock()) { buffer, promise in
				let bytes = Array(UnsafeBufferPointer(start: buffer.baseAddress, count: buffer.count))
				c.accessContext { contextPointer in
					contextPointer.pointee.write(self.wrapOutboundOut(InterfaceInstruction.encryptAndTransmit(key, bytes)), promise:promise)
				}
			 }

			// Sending data until snd_buf is full
			if(pendingPackets[key] != nil) {
				while true {
					// Next packet to be sent
					let nextPacketIterator = packetIterators[key]!.nextIterator()!
					// Check if the next is the head. If so, then we are at the end.
					guard let node = nextPacketIterator.current() else { break }
					
					do {
						var data = node.1
						// Successfully send a packet and then move iterator to next
						let sent = try kcp[key]!.send(&data, count:data.count, assosiatedData: nil)
						if(sent == 0) { break }
						packetIterators[key]! = nextPacketIterator
					} catch let error {
						logger.error("error sending kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
					}
				}
			}
			
			// Check acks to see if we can remove stuff from the pending packets
			while true {
				guard let list = pendingPackets[key],
					  let frontNode = list.front else {
					break
				}
				let chunks = (frontNode.value!.count + Int(kcp[key]!.mss - 1)) / Int(kcp[key]!.mss)
				if(chunks + ackCounter <= kcp[key]!.snd_una) {
					if(packetIterators[key]!.current() != nil) {
						if(frontNode === packetIterators[key]!.current()!.0) {
							packetIterators[key] = pendingPackets[key]!.makeLoopingIterator()
						}
					}
					
					
					_ = pendingPackets[key]!.popFront()
					ackCounter += chunks
					print((frontNode.value!.count / Int(kcp[key]!.mss)) )
					print(ackCounter)
					print(kcp[key]!.snd_una)
					print("Pending Packets Removed")
				} else {
					break
				}
			}
			
			
			rcvLoop: while true {
				do {
					let receivedData = try self.kcp[key]!.receive()
					print("Received Data")
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
			case .transitData(let key, _, let data):
				if (kcp[key] == nil) {
					makeIkcpCb(key:key, context:context)
					kcpUpdates(for:key, context:context)
				}
				do {
					_ = try kcp[key]!.input(data, count: data.count)
				} catch let error {
					logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
				}
			case .handshakeCompleted(let pubkey, let peerIndex):
				logger.notice("configuring for handshake", metadata:["peer_index":"\(peerIndex)", "peer_public_key":"\(pubkey)"])
				kcp_peers[peerIndex] = ()
		}
	}
	
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
			kcpUpdates(for: key, context: context)
		}

		// Create new linket list and iterators if it doesn't exist yet
		if(pendingPackets[key] == nil) {
			pendingPackets[key] = LinkedList<[UInt8]>()
			packetIterators[key] = pendingPackets[key]!.makeLoopingIterator()
		}
		pendingPackets[key]!.addTail(data)
	}
	
	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as PipelineEvent:
				switch evt {
					case let .reKeyEvent(key):
						// Resetting everything
						if(kcpKillTasks[key] != nil) {
							kcpUpdateTasks[key]!.cancel()
						}
						ackCounter = 0
						kcp[key] = nil
						
						
						// Starting up processes again
						makeIkcpCb(key:key, context:context)
						
						// Sending data until snd_buf is full
						if(pendingPackets[key] == nil) {
							pendingPackets[key] = LinkedList<[UInt8]>()
						}
						packetIterators[key] = pendingPackets[key]!.makeLoopingIterator()
						
						kcpUpdates(for: key, context: context)
				}
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}
