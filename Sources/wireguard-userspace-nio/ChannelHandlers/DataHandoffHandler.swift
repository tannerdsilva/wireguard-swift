import NIO
import RAW
import RAW_dh25519
import bedrock_fifo
import bedrock_future
import Logging

/// this is a handler that sits at the end of the pipeline that hands off the Inbound data to a FIFO that the end-user can use to consume the data asynchronously.
internal final class DataHandoffHandler:Sendable, ChannelInboundHandler {
	/// the type of data that this handler will receive from upstream in the inbound pipeline. this is the last inbound element in the pipeline so the inbound type is fairly high-level.
	internal typealias InboundIn = PeerAssociated<ByteBuffer>
	/// the type of object that this handler will pass to the next handler in the pipeline. since this is the last inbound handler in the pipeline, this type is `Never` to indicate that no further inbound data will be passed downstream.
	internal typealias InboundOut = Never

	/// the FIFO that will be used to hand off data to the end-user
	private let handoff:FIFO<(PublicKey, [UInt8]), Swift.Error>

	/// the logger that will be used to log events in this handler.
	private let log:Logger

	/// initializes a data handoff handler with the given FIFO instance and log level.
	internal init(handoff hoFIFO:FIFO<(PublicKey, [UInt8]), Swift.Error>, logLevel:Logger.Level) {
		handoff = hoFIFO
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		log = buildLogger
	}

	/// the function that is called when the handoff handler is added to the pipeline.
	internal func handlerAdded(context:ChannelHandlerContext) {
		let logger = log
		logger.trace("handler added to NIO pipeline.")
	}
	
	/// the function that is called when the handoff handler is removed from the pipeline.
	internal func handlerRemoved(context:ChannelHandlerContext) {
		let logger = log
		logger.trace("handler removed from NIO pipeline.")
		handoff.finish()
	}

	/// the function that is called when an error is caught in the pipeline. this will close the channel and finish the FIFO with the error.
	internal func errorCaught(context: ChannelHandlerContext, error:any Error) {
		let logger = log
		logger.error("error caught in NIO pipeline. this error will be used to close the channel.", metadata:["error":"\(String(describing:error))"])
		handoff.finish(throwing:error)
		context.channel.close(promise:nil)
	}
	
	/// the function that is called when data is read from the channel. this will hand off the data to the FIFO.
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let logger = log
		var unwrapInboundIn = self.unwrapInboundIn(data)
		handoff.yield((unwrapInboundIn.publicKey, unwrapInboundIn.associatedValue.readBytes(length:unwrapInboundIn.associatedValue.readableBytes) ?? []))
		logger.trace("handing off data to FIFO")
	}
}