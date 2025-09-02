import NIO
import RAW
import RAW_dh25519
import bedrock_fifo
import bedrock_future
import Logging

/// this is a handler that sits at the end of the pipeline that hands off the Inbound data to a FIFO that the end-user can use to consume the data asynchronously.
internal final class DataHandoffHandler<TransactableDataType>:ChannelInboundHandler, Sendable where TransactableDataType:RAW_decodable, TransactableDataType:RAW_encodable, TransactableDataType:Sendable {
	internal typealias InboundIn = (PublicKey, TransactableDataType)
	internal typealias InboundOut = Never

	/// the FIFO that will be used to hand off data to the end-user
	private let handoff:FIFO<(PublicKey, TransactableDataType), Swift.Error>

	private let log:Logger

	internal init(handoff hoFIFO:FIFO<(PublicKey, TransactableDataType), Swift.Error>, logLevel:Logger.Level) {
		handoff = hoFIFO
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
	}
	internal func handlerAdded(context:ChannelHandlerContext) {
		var logger = log
		logger.trace("handler added to NIO pipeline.")
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		var logger = log
		logger.trace("handler removed from NIO pipeline.")
	}

	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		var logger = log
		logger.trace("handing off data to FIFO")
		handoff.yield(unwrapInboundIn(data))
	}
}
