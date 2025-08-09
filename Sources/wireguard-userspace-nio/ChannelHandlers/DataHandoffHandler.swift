import NIO
import RAW_dh25519
import bedrock_fifo

/// this is a handler that sits at the end of the pipeline that hands off the Inbound data to a FIFO that the end-user can use to consume the data asynchronously.
internal final class DataHandoffHandler:ChannelInboundHandler, Sendable {
	internal typealias InboundIn = (PublicKey, [UInt8])
	internal typealias InboundOut = Never
	/// the FIFO that will be used to hand off data to the end-user
	private let handoff:FIFO<(PublicKey, [UInt8]), Swift.Error>

	internal init(handoff hoFIFO:FIFO<(PublicKey, [UInt8]), Swift.Error>) {
		handoff = hoFIFO
	}

	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		handoff.yield(unwrapInboundIn(data))
	}
}