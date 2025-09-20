import NIO
import RAW
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

extension KCPSegment {
	/// this represents a decoded kcp segment that is associated with a public key.
	internal struct PipelineDecoded {
		/// the public key that the segment is associated with
		internal let publicKey:PublicKey
		/// the kcp segment that is being passed
		internal var segment:KCPSegment
	}

	/// this represents an encoded kcp segment that is associated with a public key.
	internal struct PipelineEncoded {
		/// the public key that the segment is associated with
		internal let publicKey:PublicKey
		/// the kcp segment that is being passed
		internal var buffer:ByteBuffer
	}

	internal final class Handler:ChannelDuplexHandler, @unchecked Sendable {

		/// the type that comes into the channel from the previous handler
		internal typealias InboundIn = PipelineEncoded
		/// the type that goes out of the channel to the next handler
		internal typealias InboundOut = PipelineDecoded

		/// the type that comes into the channel from the previous writer
		internal typealias OutboundIn = PipelineDecoded
		/// the type that goes out of the channel to the next writer
		internal typealias OutboundOut = PipelineEncoded

		/// the logger that is used for logging within this handler
		private let log:Logger
		/// the mtu for the data payload within a kcp segment
		private let dataMTU:UInt16

		/// a buffer that is used for encoding segments to avoid reallocating on every write
		private var encodeBuffer:ByteBuffer! = nil

		internal init(mtu:UInt16, logLevel:Logger.Level) {
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			log = buildLogger
			dataMTU = mtu
		}
	}
}

// MARK: Basic Events
extension KCPSegment.Handler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		encodeBuffer = context.channel.allocator.buffer(capacity:Int(dataMTU))
		log.debug("handler added to NIO pipeline.", metadata:["mtu":"\(dataMTU)"])
	}

	internal func handlerRemoved(context:ChannelHandlerContext) {
		encodeBuffer = nil
		log.debug("handler removed from NIO pipeline.")
	}

	internal func userInboundEventTriggered(context:ChannelHandlerContext, event:Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
}

// MARK: Channel Read
extension KCPSegment.Handler {
	/// the error that is thrown when a kcp segment fails to parse from an inbound byte buffer
	internal struct ParseFailure:Sendable, Swift.Error {}
	/// the standard swiftnio channel read function that is called when data is read from the previous handler in the pipeline.
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let logger = log
		var encodedInbound = unwrapInboundIn(data)
		guard let segment = KCPSegment(decode:&encodedInbound.buffer) else {
			logger.error("failed to decode kcp segment from byte buffer.", metadata:["public_key":"\(encodedInbound.publicKey)"])
			context.fireErrorCaught(ParseFailure())
			return
		}
		context.fireChannelRead(wrapInboundOut(KCPSegment.PipelineDecoded(publicKey:encodedInbound.publicKey, segment:segment)))
	}
}

// MARK: Channel Write
extension KCPSegment.Handler {
	/// thrown when a handler in the outbound pipeline attempts to write a kcp segment that exceeds the configured mtu.
	internal struct MTUExceeded:Sendable, Swift.Error {
		/// the absolute maximum transmission unit that was configured for this handler.
		internal let mtu:UInt16
		/// the maximum segment size that was calculated based on the configured mtu.
		internal let mss:UInt16
		/// the padded length of the kcp segment that was attempted to be written.
		internal let paddedLength:Int
	}
	/// the standard swiftnio channel write function that is called when data is written to the next handler in the pipeline.
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let logger = log
		let decodedOutbound = unwrapOutboundIn(data)
		let expectedEncodedLength = decodedOutbound.segment.header.dataLength + UInt32(MemoryLayout<KCPSegment.Header>.size)
		guard expectedEncodedLength <= dataMTU else {
			logger.error("attempted to write kcp segment that exceeds configured mtu.", metadata:["mtu":"\(dataMTU)", "data_length":"\(decodedOutbound.segment.header.dataLength)", "public_key":"\(decodedOutbound.publicKey)"])
			let error = MTUExceeded(mtu:dataMTU, mss:dataMTU - UInt16(MemoryLayout<KCPSegment.Header>.size), paddedLength:Int(expectedEncodedLength))
			context.fireErrorCaught(error)
			promise?.fail(error)
			return
		}
		logger.trace("writing kcp segment to next handler in pipeline...", metadata:["data_length":"\(decodedOutbound.segment.header.dataLength)", "public-key_remote":"\(decodedOutbound.publicKey)", "kcp_conversation_id":"\(decodedOutbound.segment.header.conversationID)", "kcp_command":"\(decodedOutbound.segment.header.command)", "kcp_sequence_number":"\(decodedOutbound.segment.header.sequenceNumber)"])
		encodeBuffer.clear(minimumCapacity:Int(expectedEncodedLength))
		decodedOutbound.segment.encode(to:&encodeBuffer)
		context.write(wrapOutboundOut(KCPSegment.PipelineEncoded(publicKey:decodedOutbound.publicKey, buffer:encodeBuffer)), promise:promise)
	}
}

extension KCPSegment.Handler.MTUExceeded:CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(String(describing:Self.self))(mtu:\(mtu), mss:\(mss), paddedLength:\(paddedLength))"
	}
}