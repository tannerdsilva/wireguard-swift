
import NIO
import RAW
import RAW_dh25519
import kcp_swift
import Logging

extension Array {
	func split(intoChunksOf chunkSize: Int) -> [[Element]] {
		guard chunkSize > 0 else { return [self] }   // safety guard

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

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
fileprivate struct EncodedUInt32:Sendable {}

// SIVA Splicers (0_0)
internal final class SplicerHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, [UInt8]) // From kcp handler, needs to be stitched together
	public typealias InboundOut = (PublicKey, [UInt8]) // Send to the Handoff handler
	
	internal typealias OutboundIn = (PublicKey, [UInt8]) // From writes from user
	internal typealias OutboundOut = (PublicKey, [UInt8]) // Send spliced data to kcp handler
	
	private var logger:Logger
	
	private var storedLengths:[PublicKey:Int] = [:]
	private var storedPayload:[PublicKey:[UInt8]] = [:]
	
	private let spliceByteLength:Int

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
		let (key, data) = unwrapInboundIn(data)
		
		guard let len = storedLengths[key] else {
			// Extract the UInt32 from the first 4 bytes
			let value = data.RAW_access {
				return EncodedUInt32(RAW_staticbuff:$0.baseAddress!).RAW_native()
			}
			
			// Remove the first 4 bytes from the array
			let payload = Array(data.dropFirst(4))
			
			// Only this one segment
			if(value == 0) {
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
		
		// If it's the last segment, then send the whole thing to handoff handler
		if(storedLengths[key]! == 0) {
			storedLengths[key] = nil
			logger.debug("Sending reforged message to DHH")
			context.fireChannelRead(wrapInboundOut((key, storedPayload[key]!)))
			storedPayload[key] = nil
		}
	}
	
	// Receiving data which needs to be spliced and sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		
		logger.debug("Splicing \(data.count) bytes")
		
		// Data doesn't need to be spliced, add a header signifying 0 length
		if(data.count <= spliceByteLength) {
			let headerBytes = [UInt8](repeating: 0, count: 4)
			
			data.insert(contentsOf: headerBytes, at: 0)
			
			context.writeAndFlush(wrapOutboundOut((key, data)), promise: promise)
		}
		// Data needs to be spliced and place a len header on first segment
		else {
			let splices = data.split(intoChunksOf: spliceByteLength)
			let headerBytes = EncodedUInt32(RAW_native:UInt32(splices.count))
			for i in 0..<splices.count {
				var segment = Array(splices[i])
				if(i == 0) {
					headerBytes.RAW_access {
						segment.insert(contentsOf:$0, at: 0)
					}
				}
				if(i == splices.count-1) {
					context.writeAndFlush(wrapOutboundOut((key, segment)), promise: promise)
				} else {
					context.writeAndFlush(wrapOutboundOut((key, segment)), promise: nil)
				}
			}
		}
	}
}
