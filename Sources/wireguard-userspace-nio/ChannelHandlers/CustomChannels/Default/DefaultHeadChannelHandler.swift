import NIO
import Logging

/// The default head handler for a WireGuard pipeline.
///
/// Passes inbound and outbound data to the next handler in the pipeline unchanged.
public final class DefaultHeadChannelHandler:PeerAssociatedHeadHandler, @unchecked Sendable {
	/// The type that comes into the channel from the previous handler.
	public typealias InboundIn = PeerAssociated<ByteBuffer>
	/// The type that goes out of the channel to the next handler.
	public typealias InboundOut = PeerAssociated<ByteBuffer>
	
	/// The type that comes into the channel from the previous writer.
	public typealias OutboundIn = PeerAssociated<ByteBuffer>
	/// The type that goes out of the channel to the next writer.
	public typealias OutboundOut = PeerAssociated<ByteBuffer>

	/// The logger instance for this handler.
	private let log:Logger

	/// Creates a new default head channel.
	/// - Parameter logLevel: The level at which this handler logs.
	public init(logLevel:consuming Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
	}
}

// MARK: Events
extension DefaultHeadChannelHandler {
	/// Called when the handler is added to the pipeline.
	public func handlerAdded(context:borrowing ChannelHandlerContext) {
		log.debug("handler added to pipeline.")
	}
	
	/// Called when the handler is removed from the pipeline.
	public func handlerRemoved(context:borrowing ChannelHandlerContext) {
		log.debug("handler removed from pipeline.")
	}

	/// Passes any user inbound event to the next handler in the pipeline.
	public func userInboundEventTriggered(context:borrowing ChannelHandlerContext, event:Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
}

// MARK: Read
extension DefaultHeadChannelHandler {
	/// Passes inbound data to the next handler in the pipeline unchanged.
	public func channelRead(context:borrowing ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.fireChannelRead(data)
	}
}

// MARK: Write
extension DefaultHeadChannelHandler {
	/// Passes outbound data to the next handler in the pipeline unchanged.
	public func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.write(data, promise:promise)
	}

	/// Flushes outbound data to the next handler in the pipeline.
	public borrowing func flush(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.flush()
	}
}
