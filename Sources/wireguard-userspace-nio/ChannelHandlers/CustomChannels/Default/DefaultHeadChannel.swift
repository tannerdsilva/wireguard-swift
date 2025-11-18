import NIO
import Logging

public final class DefaultHeadChannel:PeerAssociatedHeadHandler, @unchecked Sendable {
	public typealias InboundIn = PeerAssociated<ByteBuffer>
	public typealias InboundOut = PeerAssociated<ByteBuffer>
	
	public typealias OutboundIn = PeerAssociated<ByteBuffer>
	public typealias OutboundOut = PeerAssociated<ByteBuffer>

	/// logger instance for this handler
	private let log:Logger

	public init(logLevel:consuming Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
	}
}

// MARK: Events
extension DefaultHeadChannel {
	public func handlerAdded(context:borrowing ChannelHandlerContext) {
		log.debug("handler added to pipeline.")
	}
	
	public func handlerRemoved(context:borrowing ChannelHandlerContext) {
		log.debug("handler removed from pipeline.")
	}

	public func userInboundEventTriggered(context:borrowing ChannelHandlerContext, event:Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
}

// MARK: Read
extension DefaultHeadChannel {
	public func channelRead(context:borrowing ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.fireChannelRead(data)
	}
}

// MARK: Write
extension DefaultHeadChannel {
	public func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.write(data, promise:promise)
	}

	public borrowing func flush(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.flush()
	}
}
