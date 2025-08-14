import NIO
import RAW
import RAW_dh25519
import bedrock_fifo
import bedrock_future
import Logging
import wireguard_crypto_core

/// this is a handler that sits at the end of the pipeline that hands off the Inbound data to a FIFO that the end-user can use to consume the data asynchronously.
internal final class DataHandoffHandler<TransactableDataType>:ChannelInboundHandler, Sendable where TransactableDataType:RAW_decodable, TransactableDataType:RAW_encodable, TransactableDataType:Sendable {
	internal typealias InboundIn = (PublicKey, TransactableDataType)
	internal typealias InboundOut = Never

	/// the FIFO that will be used to hand off data to the end-user
	private let handoff:FIFO<(PublicKey, TransactableDataType), Swift.Error>
	private let channelEnabledFuture:Future<Void, Swift.Error>

	private let log:Logger

	internal init(handoff hoFIFO:FIFO<(PublicKey, TransactableDataType), Swift.Error>, channelEnabledFuture cef:Future<Void, Swift.Error>, logLevel:Logger.Level) {
		handoff = hoFIFO
		channelEnabledFuture = cef
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
	}
	internal func handlerAdded(context:ChannelHandlerContext) {
		var logger = log
		logger[metadataKey:"_func"] = "\(#function)"
		logger[metadataKey:"listening_socket_ep"] = "\(Endpoint(context.channel.localAddress!))"
		logger[metadataKey:"listening_socket"] = "\(context.channel.localAddress!)"
		logger.trace("handler added to NIO pipeline.")
		do {
			try channelEnabledFuture.setSuccess(())
		} catch let error {
			logger.critical("failed to set channel enabled future to success", metadata:["error":"\(error)"])
			fatalError("internal error in wireguard nio implementation. error '\(error)'. this should never happen under normal circumstances. \(#file):\(#line)")
		}
	}
	internal func handlerRemoved(context:ChannelHandlerContext) {
		var logger = log
		logger[metadataKey:"_func"] = "\(#function)"
		logger.trace("handler removed from NIO pipeline.")
	}

	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		var logger = log
		logger.trace("handing off data to FIFO")
		handoff.yield(unwrapInboundIn(data))
	}
}