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
/// The channel attaches a 4-byte length to the first segment, indicating the
/// number of spliced segments to expect.
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
	
	private var storedLengths:[PublicKey:Int] = [:]
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
	/// or stores the segment if more are expected.
	/// - Parameters:
	///   - context: The channel handler context.
	///   - data: The inbound spliced segment.
	public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let inboundIn = unwrapInboundIn(data)
		let key = inboundIn.publicKey
		let byteBuffer = inboundIn.associatedValue
		let data: [UInt8] = byteBuffer.getBytes(at: byteBuffer.readerIndex, length: byteBuffer.readableBytes)!
		
		guard storedLengths[key] != nil else {
			// Extract the UInt32 from the first 4 bytes
			let value = data.RAW_access {
				return EncodedUInt32(RAW_staticbuff:$0.baseAddress!.advanced(by: data.count-4)).RAW_native()
			}
			
			// Remove the first 4 bytes from the array
			let payload = Array(data.dropLast(4))

			let buf = context.channel.allocator.buffer(bytes:payload)
			
			if (value == 0) {
				logger.debug("Sending single message to DHH")
				context.fireChannelRead(wrapInboundOut(PeerAssociated(publicKey: key, associatedValue: buf)))
				return
			}
			
			// add to stored segments cause there are more coming!
			storedLengths[key] = Int(value) - 1
			storedPayload[key] = buf
			return
		}

		storedPayload[key]!.writeBytes(data)
		storedLengths[key]! -= 1
		
		// if it's the last segment, then send the whole thing to handoff handler
		if (storedLengths[key]! == 0) {
			storedLengths[key] = nil
			logger.debug("Sending reforged message to DHH")
			context.fireChannelRead(wrapInboundOut(PeerAssociated(publicKey: key, associatedValue: storedPayload[key]!)))
			storedPayload[key] = nil
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
	/// the data fits within the MTU). A 4-byte count of segments is appended to
	/// the first segment, or `0` when the data is sent as a single segment.
	/// - Parameters:
	///   - context: The channel handler context.
	///   - data: The outbound data to splice.
	///   - promise: Completed when the written segments succeed or fail.
	public func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var associatedData = unwrapOutboundIn(data)
		logger.debug("splicing \(associatedData.associatedValue.readableBytes) bytes")
		if (associatedData.associatedValue.readableBytes <= spliceByteLength) {
			// there is no need to create multiple segments so we can add a zero at the end of the data.
			_ = EncodedUInt32(RAW_native:0).RAW_access { footerBytesPtr in
				associatedData.associatedValue.writeBytes(footerBytesPtr)
			}
			context.write(wrapOutboundOut(PeerAssociated(publicKey:associatedData.publicKey, associatedValue:associatedData.associatedValue)), promise:promise)
		} else {
			let splices = [UInt8](associatedData.associatedValue.readableBytesView).split(intoChunksOf: spliceByteLength)
			let footerBytes = EncodedUInt32(RAW_native:UInt32(splices.count))
			for i in 0..<splices.count {
				var segment = Array(splices[i])
				if (i == 0) {
					footerBytes.RAW_access {
						segment.append(contentsOf: $0)
					}
				}
				let buf = context.channel.allocator.buffer(bytes:segment)
				if (i == splices.count-1) {
					// Attach promise to the last segment to be written for this message
					context.write(wrapOutboundOut(PeerAssociated(publicKey:associatedData.publicKey, associatedValue:buf)), promise:promise)
				} else {
					context.write(wrapOutboundOut(PeerAssociated(publicKey:associatedData.publicKey, associatedValue:buf))).cascadeFailure(to:promise)
				}
			}
		}
	}
}
