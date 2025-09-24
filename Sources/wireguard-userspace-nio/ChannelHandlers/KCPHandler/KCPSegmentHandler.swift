import NIO
import RAW
import RAW_dh25519
import Logging
import wireguard_crypto_core

/// this represents a decoded kcp segment that is associated with a public key.
@available(*, deprecated, message:"use PeerAssociated<KCPSegment> instead")
internal typealias PeerSegment = PeerAssociated<KCPSegment>
extension PeerAssociated where AssociatedType == KCPSegment {
	@available(*, deprecated, renamed:"associatedValue")
	internal var segment:KCPSegment {
		get {
			return self.associatedValue
		}
		set {
			self.associatedValue = newValue
		}
	}

	internal init(publicKey:PublicKey, segment:KCPSegment) {
		self.init(publicKey:publicKey, associatedValue:segment)
	}
}

@available(*, deprecated, message:"use PeerAssociated<ByteBuffer> instead")
internal typealias PeerPayload = PeerAssociated<ByteBuffer>
extension PeerAssociated where AssociatedType == ByteBuffer {
	@available(*, deprecated, renamed:"associated")
	internal var buffer:ByteBuffer {
		get {
			return self.associatedValue
		}
		set {
			self.associatedValue = newValue
		}
	}

	internal init(publicKey:PublicKey, buffer:ByteBuffer) {
		self.init(publicKey:publicKey, associatedValue:buffer)
	}
}

extension KCPSegment {
	/// used to stack multiple kcp segments into a single payload less than MTU size
	internal struct MTUStacking:Sendable {
		/// the maximum transmission unit that is configured for this handler
		private let transmitMTU:UInt16

		/// stores the pending promises that were encoded into the byte buffer for each public key
		private var promiseStack:[PublicKey:[EventLoopPromise<Void>]] = [:]
		/// stores the byte buffers that are being built for each public key
		private var segmentStack:[PublicKey:ByteBuffer] = [:]

		internal init(transmitMTU:UInt16) {
			self.transmitMTU = transmitMTU
		}

		/// adds a segment to the stack for the given public key. if the segment would cause the mtu to be exceeded, the existing buffer is flushed first.
		/// - returns: true if outbound data was written to the context, false otherwise.
		@discardableResult fileprivate mutating func stack(segment:KCPSegment, for publicKey:PublicKey, promise:EventLoopPromise<Void>?, context:ChannelHandlerContext, handler:KCPSegment.Handler) -> Bool {
			let expectedEncodedLength = segment.header.dataLength + UInt32(IKCP_OVERHEAD)
			var didWrite = false
			if var hasExistingBuffer = segmentStack[publicKey] {
				// we have an existing buffer, see if we can append to it...
				if hasExistingBuffer.writableBytes < Int(expectedEncodedLength) {
					// mtu would be exceeded if we used the existing buffer, so we need to allocate a new one and flush the existing one.
					context.write(handler.wrapOutboundOut(PeerPayload(publicKey:publicKey, buffer:hasExistingBuffer))).whenComplete({ [promises = promiseStack[publicKey]!] result in
						switch result {
							case .failure(let error):
								for curElement in promises {
									curElement.fail(error)
								}
							case .success():
								for curElement in promises {
									curElement.succeed(())
								}
								break
						}
					})
					hasExistingBuffer.clear(minimumCapacity:Int(expectedEncodedLength))
					didWrite = true
					promiseStack[publicKey] = []
				}
				segment.encode(to:&hasExistingBuffer)
				segmentStack[publicKey] = hasExistingBuffer
				if promise != nil {
					promiseStack[publicKey]!.append(promise!)
				}
			} else {
				var newBuffer = context.channel.allocator.buffer(capacity:Int(expectedEncodedLength))
				segment.encode(to:&newBuffer)
				segmentStack[publicKey] = newBuffer
				if promise == nil {
					promiseStack[publicKey] = []
				} else {
					promiseStack[publicKey] = [promise!]
				}
			}
			return didWrite
		}

		fileprivate mutating func completeAll(context:ChannelHandlerContext, handler:KCPSegment.Handler) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			for (publicKey, buffer) in segmentStack {
				context.write(handler.wrapOutboundOut(PeerPayload(publicKey:publicKey, buffer:buffer))).whenComplete({ [promises = promiseStack[publicKey]!] result in
					switch result {
						case .failure(let error):
							for curElement in promises {
								curElement.fail(error)
							}
						case .success():
							for curElement in promises {
								curElement.succeed(())
							}
							break
					}
				})
			}
			segmentStack.removeAll(keepingCapacity:true)
			promiseStack.removeAll(keepingCapacity:true)
		}
	}
}

extension KCPSegment {

	internal final class Handler:ChannelDuplexHandler, @unchecked Sendable {

		/// the type that comes into the channel from the previous handler
		internal typealias InboundIn = PeerPayload
		/// the type that goes out of the channel to the next handler
		internal typealias InboundOut = PeerSegment

		/// the type that comes into the channel from the previous writer
		internal typealias OutboundIn = PeerSegment
		/// the type that goes out of the channel to the next writer
		internal typealias OutboundOut = PeerPayload

		/// the logger that is used for logging within this handler
		private let log:Logger
		/// the mtu for the data payload within a kcp segment
		private let dataMTU:UInt16

		/// a buffer that is used for encoding segments to avoid reallocating on every write
		private var encodeBuffer:ByteBuffer! = nil

		/// the primary tool for stacking segments into (up to) mtu sized buffers
		private var writtenStack:MTUStacking
		private var writtenCount:Int = 0

		internal init(mtu:UInt16, logLevel:Logger.Level) {
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			log = buildLogger
			dataMTU = mtu
			writtenStack = MTUStacking(transmitMTU: mtu)
		}

		deinit {
			log.trace("instance deinitialized.")
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
		var i = 0
		while let segment = KCPSegment(decode:&encodedInbound.buffer) {
			i += 1
			logger.debug("decoded kcp segment from byte buffer.", metadata:["public_key":"\(encodedInbound.publicKey)", "segment_sequence_number":"\(segment.header.sequenceNumber)", "segment_command":"\(segment.header.command)", "segment_data_length":"\(segment.header.dataLength)", "segment_fragment_id":"\(segment.header.fragmentID)", "segment_timestamp":"\(segment.header.timestamp)", "segment_una":"\(segment.header.una)"])
			context.fireChannelRead(wrapInboundOut(PeerSegment(publicKey:encodedInbound.publicKey, segment:segment)))
		}
		guard let segment = KCPSegment(decode:&encodedInbound.buffer) else {
			logger.error("failed to decode kcp segment from byte buffer.", metadata:["public_key":"\(encodedInbound.publicKey)"])
			context.fireErrorCaught(ParseFailure())
			return
		}
		
		context.fireChannelRead(wrapInboundOut(PeerSegment(publicKey:encodedInbound.publicKey, segment:segment)))
	}
}

// MARK: Channel Write
extension KCPSegment.Handler {
	/// the standard swiftnio channel write function that is called when data is written to the next handler in the pipeline.
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let decodedOutbound = unwrapOutboundIn(data)
		if writtenStack.stack(segment:decodedOutbound.associatedValue, for:decodedOutbound.publicKey, promise:promise, context:context, handler:self) == true {
			writtenCount += 1
		}
	}

	internal func flush(context:ChannelHandlerContext) {
		guard writtenCount > 0 else {
			return
		}
		writtenCount = 0
		writtenStack.completeAll(context:context, handler:self)
		context.flush()
	}
}