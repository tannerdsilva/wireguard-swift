import NIO
import Logging
import RAW_dh25519

/// Handler that schedules a repeated task to send an empty ByteBuffer outbound.
public final class KeepAliveHandler:PeerAssociatedHeadHandler, @unchecked Sendable {
	public typealias InboundIn = PeerAssociated<ByteBuffer>
	public typealias OutboundIn = Never
	public typealias OutboundOut = PeerAssociated<ByteBuffer>

	/// logger instance for this handler
	private let logger:Logger
	private var sendTasks:[PublicKey:RepeatedTask] = [:]
	private var config:[PeerInfo]

	public init(peers:[PeerInfo], logLevel:consuming Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		config = peers
	}
	
	private func scheduleRepeatedKeepAlives(context:ChannelHandlerContext) {
		for peer in config {
			sendTasks[peer.publicKey] = context.eventLoop.scheduleRepeatedTask(initialDelay: .seconds(0), delay: peer.internalKeepAlive ?? .seconds(15)) { [weak self, c = ContextContainer(context:context), l = logger] _ in
				guard let self = self else {
					return
				}
				c.accessContext({ contextPointer in
					l.debug("Sending Keep Alive Packet")
					let keepAlivePacket = PeerAssociated<ByteBuffer>(publicKey: peer.publicKey, associatedValue: ByteBuffer())
					contextPointer.pointee.writeAndFlush(wrapOutboundOut(keepAlivePacket), promise: nil)
				})
			}
		}
	}
}

// MARK: Events
extension KeepAliveHandler {
	public func handlerAdded(context:borrowing ChannelHandlerContext) {
		scheduleRepeatedKeepAlives(context: context)
		logger.debug("handler added to pipeline.")
	}
	
	public func handlerRemoved(context:borrowing ChannelHandlerContext) {
		for (key, task) in sendTasks {
			task.cancel()
			sendTasks[key] = nil
		}
		logger.debug("handler removed from pipeline.")
	}
	public func userInboundEventTriggered(context: ChannelHandlerContext, event:Any) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		switch event {
			case let e as InboundEvent:
				switch e {
					case .peerConfigUpdate(let newConfig, _):
						context.fireUserInboundEventTriggered(event)
						guard let peerInfo = newConfig as? [PeerInfo] else {
							return
						}
						logger.info("Configuration updated, resetting keep alive updates")
						for (key, task) in sendTasks {
							task.cancel()
							sendTasks[key] = nil
						}
						config = peerInfo
						scheduleRepeatedKeepAlives(context: context)
				}
			default:
				context.fireUserInboundEventTriggered(event)
		}
	}
}
