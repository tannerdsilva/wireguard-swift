import NIO
import RAW
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
fileprivate struct EncodedUInt64:Sendable {}

internal final class KcpHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, ByteBuffer)
	internal typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = (PublicKey, ByteBuffer)
	
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
	
	// Variables for preventing duplicate receives
	private var sendNonce:[PublicKey:UInt64] = [:]
	private var receiveNonce:[PublicKey:UInt64] = [:]
	
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
		kcp[key]!.setNoDelay(1, interval: 30, resend: 1, nc: 0)
	}

	private func kcpUpdates(for key:PublicKey, context:ChannelHandlerContext) {
		guard kcpUpdateTasks[key] == nil else { return }
		kcpStartTimers[key] = 0
		
		let task = context.eventLoop.scheduleRepeatedTask(initialDelay: kcpUpdateTime, delay: kcpUpdateTime) {
			[weak self, c = ContextContainer(context:context)] _ in
			guard let self = self else { return }
			
			self.kcp[key]!.update(current:iclock()) { buffer, promise in
				let rawPointer = UnsafeRawBufferPointer(buffer)
				let byteBuffer = ByteBuffer(bytes: rawPointer)
				c.accessContext { contextPointer in
					contextPointer.pointee.write(self.wrapOutboundOut((key, byteBuffer)), promise:promise)
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
				} else {
					break
				}
			}
			
			
			rcvLoop: while true {
				do {
					var receivedData = try self.kcp[key]!.receive()
					// Extract the UInt64 from the last 8 bytes
					let value = receivedData.RAW_access {
						return EncodedUInt64(RAW_staticbuff:$0.baseAddress!.advanced(by: receivedData.count-8)).RAW_native()
					}
					
					// Check if the receiver has disconnected. If so, update to match the sender
					if(value == 0) {
						receiveNonce[key]! = value
					}
					// Check if it's not duplicate data
					if(value >= receiveNonce[key]!) {
						// Remove the first 4 bytes from the array
						receivedData = Array(receivedData.dropLast(8))
						c.accessContext { contextPointer in
							contextPointer.pointee.fireChannelRead(wrapInboundOut((key, receivedData)))
						}
						receiveNonce[key]! = value + 1
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
		let (key, data) = unwrapInboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
			kcpUpdates(for:key, context:context)
		}
		if(sendNonce[key] == nil) {
			sendNonce[key] = 0
			receiveNonce[key] = 0
		}
		var bytes: [UInt8] = data.getBytes(at: data.readerIndex, length: data.readableBytes)!
		
		do {
			_ = try kcp[key]!.input(bytes, count: bytes.count)
		} catch let error {
			logger.error("error reading kcp data", metadata:["peer_public_key":"\(key)", "error_thrown":"\(error)"])
		}
	}
	
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			makeIkcpCb(key:key, context:context)
			kcpUpdates(for: key, context: context)
		}
		if(sendNonce[key] == nil) {
			sendNonce[key] = 0
			receiveNonce[key] = 0
		}
		let footerBytes = EncodedUInt64(RAW_native:sendNonce[key]!)
		footerBytes.RAW_access {
			data.append(contentsOf: $0)
		}
		sendNonce[key]! += 1

		// Create new linket list and iterators if it doesn't exist yet
		if(pendingPackets[key] == nil) {
			pendingPackets[key] = LinkedList<[UInt8]>()
			packetIterators[key] = pendingPackets[key]!.makeLoopingIterator()
		}
		pendingPackets[key]!.addTail(data)
	}
	
	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as WireguardHandler.WireguardHandshakeNotification:
				print("resetting")
				let key = evt.publicKey
				if(sendNonce[key] == nil) {
					sendNonce[key] = 0
					receiveNonce[key] = 0
				}
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
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}
