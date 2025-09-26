import NIO
import RAW
import RAW_dh25519
import Logging

extension Array {
	func split(intoChunksOf chunkSize: Int) -> [[Element]] {
		guard chunkSize > 0 else { return [self] }	// safety guard
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
	internal typealias InboundIn = (PublicKey, ByteBuffer) // From kcp handler, needs to be stitched together
	public typealias InboundOut = (PublicKey, [UInt8]) // Send to the Handoff handler
	
	internal typealias OutboundIn = (PublicKey, [UInt8]) // From writes from user
	internal typealias OutboundOut = (PublicKey, ByteBuffer) // Send spliced data to kcp handler
	
	private var logger:Logger
	
	private var storedLengths:[PublicKey:Int] = [:]
	private var storedPayload:[PublicKey:[UInt8]] = [:]
	
	private let spliceByteLength:Int

	private var pendingWrites:[(payload:(PublicKey, ByteBuffer), promise:EventLoopPromise<Void>?)] = []

	internal init(logLevel:Logger.Level, spliceByteLength:Int) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		self.spliceByteLength = spliceByteLength
	}

	internal func handlerAdded(context: ChannelHandlerContext) {
		logger[metadataKey:"listening_socket"] = "\(context.channel.localAddress!)"
		logger.trace("handler added to pipeline.")
	}

	// Received kcp segment. Need to stitch together and send to handoff handler
	internal func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let (key, byteBuffer) = unwrapInboundIn(data)
		let data: [UInt8] = byteBuffer.getBytes(at: byteBuffer.readerIndex, length: byteBuffer.readableBytes)!
		
		guard storedLengths[key] != nil else {
			// Extract the UInt32 from the first 4 bytes
			let value = data.RAW_access {
				return EncodedUInt32(RAW_staticbuff:$0.baseAddress!.advanced(by: data.count-4)).RAW_native()
			}
			
			// Remove the first 4 bytes from the array
			let payload = Array(data.dropLast(4))
			
			// Only this one segment
			if (value == 0) {
				logger.debug("Sending single message to DHH")
				context.fireChannelRead(wrapInboundOut((key, payload)))
				return
			}
			
			// Add to stored segments cause there are more coming!
			storedLengths[key] = Int(value) - 1
			storedPayload[key] = payload
			
			return
		}
		
		storedPayload[key]!.append(contentsOf: data)
		storedLengths[key]! -= 1
		
		// if it's the last segment, then send the whole thing to handoff handler
		if (storedLengths[key]! == 0) {
			storedLengths[key] = nil
			logger.debug("Sending reforged message to DHH")
			context.fireChannelRead(wrapInboundOut((key, storedPayload[key]!)))
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

	internal func channelWritabilityChanged(context: ChannelHandlerContext) {
		defer {
			context.fireChannelWritabilityChanged()
		}
		logger.trace("channel writability changed: \(context.channel.isWritable)")
		guard context.channel.isWritable == true else {
			logger.notice("backpressure in channel detected.")
			return
		}
		logger.trace("channel is writable, flushing buffered writes...")
		for ((publicKey, buffer), promise) in pendingWrites {
			logger.trace("writing buffered packet...", metadata:["bytes_written":"\(buffer.readableBytes)", "remote_address":"\(publicKey)"])
			context.writeAndFlush(wrapOutboundOut((publicKey, buffer)), promise:promise)
		}
		// context.flush()
		pendingWrites.removeAll()
	}

	private func writeOrStore(context:ChannelHandlerContext, key:PublicKey, buffer:ByteBuffer, promise:EventLoopPromise<Void>?) {
		if context.channel.isWritable == false {
			logger.notice("channel is not writable, buffering packet write...", metadata:["buffered_writes":"\(pendingWrites.count + 1)"])
			pendingWrites.append((payload:(key, buffer), promise:promise))
		} else {
			logger.trace("writing spliced packet...", metadata:["bytes_written":"\(buffer.readableBytes)"])
			context.writeAndFlush(wrapOutboundOut((key, buffer)), promise: promise)
		}
	}
	
	// Receiving data which needs to be spliced and sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		
		logger.debug("Splicing \(data.count) bytes")
		
		// Data doesn't need to be spliced, add a header signifying 0 length
		if (data.count <= spliceByteLength) {
			let footerBytes = [UInt8](repeating: 0, count: 4)
			data.append(contentsOf: footerBytes)
			let buf = context.channel.allocator.buffer(bytes:data)
			writeOrStore(context:context, key:key, buffer:buf, promise:promise)
		} else {
			let splices = data.split(intoChunksOf: spliceByteLength)
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
					writeOrStore(context:context, key:key, buffer:buf, promise:promise)
				} else {
					writeOrStore(context:context, key:key, buffer:buf, promise:nil)
				}
			}
		}
	}
}
