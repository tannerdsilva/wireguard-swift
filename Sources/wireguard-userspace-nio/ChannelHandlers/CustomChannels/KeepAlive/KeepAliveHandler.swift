import NIO
import Logging
import RAW_dh25519

/// A head handler that schedules a repeated task sending an empty outbound
/// `ByteBuffer` for each configured peer.
public final class KeepAliveHandler:PeerAssociatedHeadHandler, @unchecked Sendable {
	/// The type that comes into the channel from the previous handler.
	public typealias InboundIn = PeerAssociated<ByteBuffer>
	/// Keep-alives are outbound-only; nothing comes in from the writer side.
	public typealias OutboundIn = Never
	/// The type that goes out of the channel to the next writer.
	public typealias OutboundOut = PeerAssociated<ByteBuffer>

	/// The logger instance for this handler.
	private let logger:Logger
	private var sendTasks:[PublicKey:RepeatedTask] = [:]
	private var config:[PeerInfo]

	/// Creates a keep-alive head handler.
	/// - Parameters:
	///   - peers: The peers to keep alive.
	///   - logLevel: The level at which this handler logs.
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
	/// Called when the handler is added to the pipeline; schedules the keep-alive tasks.
	public func handlerAdded(context:borrowing ChannelHandlerContext) {
		scheduleRepeatedKeepAlives(context: context)
		logger.debug("handler added to pipeline.")
	}
	
	/// Called when the handler is removed from the pipeline; cancels the keep-alive tasks.
	public func handlerRemoved(context:borrowing ChannelHandlerContext) {
		for (key, task) in sendTasks {
			task.cancel()
			sendTasks[key] = nil
		}
		logger.debug("handler removed from pipeline.")
	}
	/// Handles peer configuration updates by re-scheduling the keep-alive tasks.
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
