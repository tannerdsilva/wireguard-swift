import NIO
import RAW
import RAW_dh25519
import Logging

extension Array {
	func split(intoChunksOf chunkSize: Int) -> [[Element]] {
		guard chunkSize > 0 else { return [self] }
		var chunks: [[Element]] = []
		var startIndex = 0
		while startIndex < self.count {
			let endIndex = Swift.min(startIndex + chunkSize, self.count)
			let chunk = Array(self[startIndex..<endIndex])
			chunks.append(chunk)
			startIndex += chunkSize
		}
		return chunks
	}
}

// SIVA Splicers (0_0)
/// A channel duplex handler that splices outbound data into MTU-sized segments
/// and reassembles inbound spliced segments. Inbound data must arrive in order,
/// so this handler is only suitable for channels that guarantee ordered delivery
/// (such as KCP).
///
/// The channel prepends a 4-byte total payload length to the first segment so
/// that the receiver can locate every segment boundary exactly, even when
/// WireGuard zero-pads each encrypted plaintext to a multiple of 16 bytes.
public final class SplicerHandler:PeerAssociatedTailHandler, @unchecked Sendable {
	/// The type that comes into the channel from the previous handler.
	public typealias InboundIn = PeerAssociated<ByteBuffer>
	/// The type that goes out of the channel to the next handler.
	public typealias InboundOut = PeerAssociated<ByteBuffer>
	
	/// The type that comes into the channel from the previous writer.
	public typealias OutboundIn = PeerAssociated<ByteBuffer>
	/// The type that goes out of the channel to the next writer.
	public typealias OutboundOut = PeerAssociated<ByteBuffer>
	
	private var logger:Logger
	
	/// The number of payload bytes still expected for the in-flight message per peer.
	private var storedRemaining:[PublicKey:Int] = [:]
	/// The reassembled payload collected so far for the in-flight message per peer.
	private var storedPayload:[PublicKey:ByteBuffer] = [:]
	
	private let spliceByteLength:Int

	internal init(logLevel:Logger.Level, spliceByteLength:Int) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		self.spliceByteLength = spliceByteLength
	}

	/// Called when the handler is added to the pipeline.
	public func handlerAdded(context: ChannelHandlerContext) {
		logger.trace("handler added to pipeline.")
	}

	/// Reassembles the received segments and forwards the completed message,
	/// or stores the segment if more are expected. Each segment may carry up to
	/// 15 bytes of trailing WireGuard padding, which is discarded by consuming
	/// exactly the expected number of payload bytes.
	/// - Parameters:
	///   - context: The channel handler context.
	///   - data: The inbound spliced segment.
	public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let inboundIn = unwrapInboundIn(data)
		let key = inboundIn.publicKey
		let byteBuffer = inboundIn.associatedValue
		guard let data: [UInt8] = byteBuffer.getBytes(at: byteBuffer.readerIndex, length: byteBuffer.readableBytes) else {
			logger.error("unable to read inbound segment bytes. dropping segment.")
			return
		}

		guard let expectedRemaining = storedRemaining[key] else {
			// This is the first segment of a message: it carries a 4-byte total payload length.
			guard data.count >= MemoryLayout<EncodedUInt32>.size else {
				logger.error("inbound first segment is shorter than the 4-byte length field. dropping segment.")
				return
			}
			let totalLength = data.withUnsafeBytes { rawBuffer in
				EncodedUInt32(RAW_decode:UnsafeRawBufferPointer(rebasing:rawBuffer[0..<MemoryLayout<EncodedUInt32>.size]))!.RAW_native()
			}
			logger.debug("received first segment for a \(totalLength) byte message.")

			// The first segment carries the length field plus up to (spliceByteLength-4) payload bytes.
			let firstChunkCapacity = Swift.max(spliceByteLength - MemoryLayout<EncodedUInt32>.size, 0)
			let take = Swift.min(firstChunkCapacity, Int(totalLength), data.count - MemoryLayout<EncodedUInt32>.size)
			guard take > 0 || totalLength == 0 else {
				logger.error("inbound first segment carried fewer payload bytes than framing allows. dropping message.")
				return
			}

			let payloadBytes = Array(data[MemoryLayout<EncodedUInt32>.size..<(MemoryLayout<EncodedUInt32>.size + take)])
			let remaining = Int(totalLength) - take
			if remaining == 0 {
				// Whole single-segment message is present in this segment.
				logger.debug("Sending single message to DHH")
				let buf = context.channel.allocator.buffer(bytes:payloadBytes)
				context.fireChannelRead(wrapInboundOut(PeerAssociated(publicKey: key, associatedValue: buf)))
				return
			}

			// More segments are coming; stash the partial payload and the bytes still expected.
			var acc = context.channel.allocator.buffer(capacity:Int(totalLength))
			acc.writeBytes(payloadBytes)
			storedRemaining[key] = remaining
			storedPayload[key] = acc
			return
		}

		// Continuation segment: consume exactly the expected bytes, discarding any trailing padding.
		let take = Swift.min(expectedRemaining, spliceByteLength, data.count)
		guard take > 0 else {
			logger.error("inbound continuation segment carried no usable payload. dropping segment.")
			return
		}
		storedPayload[key]!.writeBytes(Array(data[0..<take]))
		let newRemaining = expectedRemaining - take
		if newRemaining == 0 {
			storedRemaining[key] = nil
			logger.debug("Sending reforged message to DHH")
			context.fireChannelRead(wrapInboundOut(PeerAssociated(publicKey: key, associatedValue: storedPayload[key]!)))
			storedPayload[key] = nil
		} else {
			storedRemaining[key] = newRemaining
		}
	}

	/// Called when a channel read completes; forwards the event downstream.
	public func channelReadComplete(context: ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		logger.trace("channel read complete.")
		context.fireChannelReadComplete()
	}
	
	/// Splices outbound data into MTU-sized segments (or a single segment, when
	/// the data fits within the MTU). A 4-byte total payload length is prepended
	/// to the first segment so the receiver can reassemble the message exactly;
	/// the first chunk is sized so that length field + chunk never exceed the MTU.
	/// Subsequent chunks carry no header and are at most `spliceByteLength` bytes.
	/// - Parameters:
	///   - context: The channel handler context.
	///   - data: The outbound data to splice.
	///   - promise: Completed when the written segments succeed or fail.
	public func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let associatedData = unwrapOutboundIn(data)
		let payloadBytes = [UInt8](associatedData.associatedValue.readableBytesView)
		let totalLength = payloadBytes.count
		logger.debug("splicing \(totalLength) bytes")

		// The 4-byte length field is UInt32; a single message larger than that is
		// rejected rather than trapping on the conversion.
		guard totalLength <= Int(UInt32.max) else {
			logger.error("spliced message exceeds the UInt32 length field. failing write.")
			promise?.fail(ChannelError.MessageTooLarge(attemptedOutboundSize:totalLength))
			return
		}

		let footerSize = MemoryLayout<EncodedUInt32>.size
		let firstChunkCapacity = Swift.max(spliceByteLength - footerSize, 0)

		func writeSegment(_ segmentBytes:[UInt8], attachPromise:Bool) {
			let buf = context.channel.allocator.buffer(bytes:segmentBytes)
			let segment = PeerAssociated(publicKey:associatedData.publicKey, associatedValue:buf)
			if attachPromise {
				context.write(wrapOutboundOut(segment), promise:promise)
			} else {
				context.write(wrapOutboundOut(segment)).cascadeFailure(to:promise)
			}
		}

		let footerBytes = EncodedUInt32(RAW_native:UInt32(totalLength)).RAW_access_immutable { $0.map { $0 } }

		if totalLength <= firstChunkCapacity {
			// Single segment: length field followed by the whole payload.
			writeSegment(footerBytes + payloadBytes, attachPromise:true)
			return
		}

		// First segment holds the length field plus the first chunk.
		let firstChunk = Array(payloadBytes[0..<firstChunkCapacity])
		writeSegment(footerBytes + firstChunk, attachPromise:false)

		// Remaining chunks are header-free and at most spliceByteLength each.
		let rest = Array(payloadBytes[firstChunkCapacity...])
		let chunkedRest = rest.split(intoChunksOf: spliceByteLength)
		for (index, chunk) in chunkedRest.enumerated() {
			writeSegment(chunk, attachPromise: index == chunkedRest.count - 1)
		}
	}
}
