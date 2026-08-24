import NIO
import Logging

fileprivate struct DropAllError:Sendable, Swift.Error {}

/// A tail handler that drops all inbound and outbound data.
public final class DropAllHandler:PeerAssociatedTailHandler, @unchecked Sendable {
	/// No inbound data can reach this handler.
	public typealias InboundIn = Never
	/// No outbound data leaves this handler.
	public typealias OutboundOut = Never
	
	private var logger:Logger

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}
	/// Called when the handler is added to the pipeline.
	public func handlerAdded(context: ChannelHandlerContext) { logger.trace("handler added to pipeline.") }
	/// Drops the read data.
	public func channelRead(context: ChannelHandlerContext, data: NIOAny) { logger.trace("Dropping channelRead packet") }
	/// Fails the write promise with a `DropAllError` and drops the data.
	public func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		logger.trace("Dropping write packet")
		promise?.fail(DropAllError())
	}
}
