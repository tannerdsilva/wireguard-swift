import NIO
import Logging

public final class DropAllHandler:PeerAssociatedTailHandler, @unchecked Sendable {
	public typealias InboundIn = Never
	public typealias OutboundOut = Never
	
	private var logger:Logger

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}
	public func handlerAdded(context: ChannelHandlerContext) { logger.trace("handler added to pipeline.") }
	public func channelRead(context: ChannelHandlerContext, data: NIOAny) { logger.trace("Dropping channelRead packet") }
	public func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) { logger.trace("Dropping write packet") }
}
