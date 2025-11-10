import NIO
import Logging

internal final class DefaultHeadChannel:PeerAssociatedHeadHandler, @unchecked Sendable {
	internal typealias InboundIn = PeerAssociated<ByteBuffer>
	internal typealias InboundOut = PeerAssociated<ByteBuffer>
	
	internal typealias OutboundIn = PeerAssociated<ByteBuffer>
	internal typealias OutboundOut = PeerAssociated<ByteBuffer>

	/// logger instance for this handler
	private let log:Logger

	internal init(logLevel:consuming Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
	}
}

// MARK: Events
extension DefaultHeadChannel {
	internal func handlerAdded(context:borrowing ChannelHandlerContext) {
		log.debug("handler added to pipeline.")
	}
	
	internal func handlerRemoved(context:borrowing ChannelHandlerContext) {
		log.debug("handler removed from pipeline.")
	}

	internal func userInboundEventTriggered(context:borrowing ChannelHandlerContext, event:Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
}

// MARK: Read
extension DefaultHeadChannel {
	internal func channelRead(context:borrowing ChannelHandlerContext, data:NIOAny) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.fireChannelRead(data)
	}
}

// MARK: Write
extension DefaultHeadChannel {
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) throws {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.write(data, promise:promise)
	}

	internal borrowing func flush(context:borrowing ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		context.flush()
	}
}
