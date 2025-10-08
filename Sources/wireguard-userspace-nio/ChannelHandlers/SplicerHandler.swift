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
internal final class SplicerHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = PeerAssociated<ByteBuffer> // From kcp handler, needs to be stitched together
	public typealias InboundOut = PeerAssociated<ByteBuffer> // Send to the Handoff handler
	
	internal typealias OutboundIn = PeerAssociated<ByteBuffer> // From writes from user
	internal typealias OutboundOut = PeerAssociated<ByteBuffer> // Send spliced data to kcp handler
	// private var outboundOutDriver:WriteOrHold<OutboundOut>
	
	private var logger:Logger
	
	private var storedLengths:[PublicKey:Int] = [:]
	private var storedPayload:[PublicKey:ByteBuffer] = [:]
	
	private let spliceByteLength:Int

	internal init(logLevel:Logger.Level, spliceByteLength:Int) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		self.spliceByteLength = spliceByteLength
		// outboundOutDriver = WriteOrHold(logLevel:logLevel, limit:nil)
	}

	internal func handlerAdded(context: ChannelHandlerContext) {
		logger[metadataKey:"listening_socket"] = "\(context.channel.localAddress!)"
		logger.trace("handler added to pipeline.")
	}

	// Received kcp segment. Need to stitch together and send to handoff handler
	internal func channelRead(context: ChannelHandlerContext, data: NIOAny) {
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
			
			// Only this one segment
			if (value == 0) {
				logger.debug("Sending single message to DHH")
				context.fireChannelRead(wrapInboundOut(PeerAssociated(publicKey: key, associatedValue: buf)))
				return
			}
			
			// Add to stored segments cause there are more coming!
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

	internal func channelReadComplete(context: ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		logger.trace("channel read complete.")
		context.fireChannelReadComplete()
	}
	
	// Receiving data which needs to be spliced and sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var associatedData = unwrapOutboundIn(data)
		
		logger.debug("splicing \(associatedData.associatedValue.readableBytes) bytes")
		
		// Data doesn't need to be spliced, add a header signifying 0 length
		if (associatedData.associatedValue.readableBytes <= spliceByteLength) {
			let footerBytes = [UInt8](repeating: 0, count: 4)
			associatedData.associatedValue.writeBytes(footerBytes)
			context.writeAndFlush(wrapOutboundOut(PeerAssociated(publicKey:associatedData.publicKey, associatedValue:associatedData.associatedValue)), promise:promise)
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
					context.writeAndFlush(wrapOutboundOut(PeerAssociated(publicKey:associatedData.publicKey, associatedValue:buf)), promise:promise)
				} else {
					context.writeAndFlush(wrapOutboundOut(PeerAssociated(publicKey:associatedData.publicKey, associatedValue:buf)), promise:nil)
				}
			}
		}
	}
}
