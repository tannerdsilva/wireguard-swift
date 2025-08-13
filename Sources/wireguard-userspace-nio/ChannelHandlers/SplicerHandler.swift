
import NIO
import RAW_dh25519
import kcp_swift
import Logging

// SIVA Splicers (0_0)
internal final class SplicerHandler:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, [UInt8]) // From kcp handler, needs to be stitched together
	public typealias InboundOut = (PublicKey, [UInt8]) // Send to the Handoff handler
	
	internal typealias OutboundIn = (PublicKey, [UInt8]) // From writes from user
	internal typealias OutboundOut = (PublicKey, [UInt8]) // Send spliced data to kcp handler
	
	private let logger:Logger
	
	private var storedLengths:[PublicKey:Int] = [:]
	private var storedPayload:[PublicKey:[UInt8]] = [:]

	internal init(logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
	}
	
	// Received kcp segment. Need to stitch together and send to handoff handler
	internal func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let (key, data) = unwrapInboundIn(data)
		
		guard let len = storedLengths[key] else {
			// Extract the UInt32 from the first 4 bytes
			let value = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
			
			// Remove the first 4 bytes from the array
			let payload = Array(data.dropFirst(4))
			
			// Only this one segment
			if(value != 0) {
				storedLengths[key] = Int(value) - 1
				context.fireChannelRead(wrapInboundOut((key, payload)))
			}
			
			// Add to stored segments cause there are more coming!
			storedPayload[key] = payload
			
			return
		}
		
		storedPayload[key]!.append(contentsOf: data)
		storedLengths[key]! -= 1
		
		// If it's the last segment, then send the whole thing to handoff handler
		if(storedLengths[key]! == 0) {
			storedLengths[key] = nil
			context.fireChannelRead(wrapInboundOut((key, storedPayload[key]!)))
		}
	}
	
	// Receiving data which needs to be spliced and sent
	internal func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		
		// Data doesn't need to be spliced, add a header signifying 0 length
		if(data.count <= 300_000) {
			let headerBytes = [UInt8](repeating: 0, count: 4)
			
			data.insert(contentsOf: headerBytes, at: 0)
			
			context.writeAndFlush(wrapOutboundOut((key, data)), promise: promise)
		}
		// Data needs to be spliced and place a len header on first segment
		else {
			let len = (data.count + 299_999) / 300_000
			let header:UInt32 = UInt32(len)
			
			var headerBytes = withUnsafeBytes(of: header.bigEndian) { Array($0) }

			for i in 0..<len {
				var segment = Array(data[data.index(data.startIndex, offsetBy: i * 300_000)..<data.index(data.startIndex, offsetBy: (i + 1) * 300_000)])
				if(i == 0) {
					segment.insert(contentsOf: headerBytes, at: 0)
				}
				context.writeAndFlush(wrapOutboundOut((key, segment)), promise: promise)
			}
		}
	}
}
