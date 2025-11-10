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
	fileprivate struct MTUStacking:Sendable {
		/// the logger that is used for logging within this struct
		private let log:Logger

		private let mtu:MTULimits

		/// stores the pending promises that were encoded into the byte buffer for each public key
		private var promiseStack:[PublicKey:[EventLoopPromise<Void>]] = [:]
		/// stores the byte buffers that are being built for each public key
		private var segmentStack:[PublicKey:ByteBuffer] = [:]

		internal init(privateKey:MemoryGuarded<PrivateKey>, mtu:MTULimits, logLevel:consuming Logger.Level) {
			self.mtu = mtu
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			buildLogger[metadataKey:"public-key_self"] = "\(PublicKey(privateKey:privateKey))"
			log = buildLogger
			buildLogger.trace("instance initialized.", metadata:["mtu_outboundOut":"\(mtu.mtuOutboundOut)"])
		}

		/// adds a segment to the stack for the given public key. if the segment would cause the mtu to be exceeded, the existing buffer is flushed first.
		/// - returns: true if outbound data was written to the context, false otherwise.
		@discardableResult fileprivate mutating func stack(context:borrowing ChannelHandlerContext, segment:KCPSegment, for publicKey:PublicKey, promise:EventLoopPromise<Void>?, handler:KCPSegment.Handler) -> Bool {
			let expectedEncodedLength = segment.header.dataLength + UInt16(IKCP_OVERHEAD)
			var didWrite = false
			if var hasExistingBuffer = segmentStack[publicKey] {
				// we have an existing buffer, see if we can append to it...
				if hasExistingBuffer.readableBytes + Int(expectedEncodedLength) > mtu.mtuOutboundOut {
					// initialize a new promise that will be used to track the completion of the write
					#if DEBUG
					// validate mtu outboundout
					guard hasExistingBuffer.readableBytes <= mtu.mtuOutboundOut else {
						log.warning("outboundOut contains data that exceeds the configured mtu.", metadata:["mtu_outboundOut":"\(mtu.mtuOutboundOut)", "size":"\(hasExistingBuffer.readableBytes)"])
						return didWrite
					}
					#endif
					let writePromise = context.channel.eventLoop.makePromise(of:Void.self)
					for curElement in promiseStack[publicKey]! {
						writePromise.futureResult.cascade(to:curElement)
					}
					context.write(handler.wrapOutboundOut(PeerAssociated<ByteBuffer>(publicKey:publicKey, associatedValue:hasExistingBuffer)), promise:writePromise)
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
				didWrite = true
			}
			return didWrite
		}

		fileprivate mutating func completeAll(context:borrowing ChannelHandlerContext, handler:borrowing KCPSegment.Handler) {
			#if DEBUG
			context.eventLoop.assertInEventLoop()
			#endif
			processLoop: for (publicKey, buffer) in segmentStack {
				#if DEBUG
				// validate mtu outboundout
				guard buffer.readableBytes <= mtu.mtuOutboundOut else {
					log.warning("outboundOut contains data that exceeds the configured mtu.", metadata:["mtu_outboundOut":"\(mtu.mtuOutboundOut)", "size":"\(buffer.readableBytes)"])
					continue processLoop
				}
				#endif
				context.write(handler.wrapOutboundOut(PeerAssociated<ByteBuffer>(publicKey:publicKey, associatedValue:buffer))).whenComplete({ [promises = promiseStack[publicKey]!] result in
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

	internal final class Handler:PeerAssociatedHeadHandler, @unchecked Sendable {

		/// the type that comes into the channel from the previous handler
		internal typealias InboundIn = PeerAssociated<ByteBuffer>
		/// the type that goes out of the channel to the next handler
		internal typealias InboundOut = PeerAssociated<KCPSegment>

		/// the type that comes into the channel from the previous writer
		internal typealias OutboundIn = PeerAssociated<KCPSegment>
		/// the type that goes out of the channel to the next writer
		internal typealias OutboundOut = PeerAssociated<ByteBuffer>

		/// the logger that is used for logging within this handler
		private let log:Logger
		/// the mtu for the data payload within a kcp segment
		private let mtu:MTULimits

		/// a buffer that is used for encoding segments to avoid reallocating on every write
		private var encodeBuffer:ByteBuffer! = nil

		/// the primary tool for stacking segments into (up to) mtu sized buffers
		private var stackedSegmentCount:Int = 0
		private var writtenStack:MTUStacking
		private var outboundOutCount:Int = 0

		internal init(privateKey:MemoryGuarded<PrivateKey>, mtu:inout MTULimits, logLevel:Logger.Level) {
			var buildLogger = Logger(label:"\(String(describing:KCPSegment.self)).\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			buildLogger[metadataKey:"public-key_self"] = "\(PublicKey(privateKey:privateKey))"
			log = buildLogger
			mtu = MTULimits(bidirectional:mtu.mtuOutboundIn)
			self.mtu = mtu
			writtenStack = MTUStacking(privateKey:privateKey, mtu:mtu, logLevel: logLevel)
		}
	}
}

// MARK: Basic Events
extension KCPSegment.Handler {
	internal func handlerAdded(context:ChannelHandlerContext) {
		encodeBuffer = context.channel.allocator.buffer(capacity:Int(mtu.mtuOutboundOut))
		log.debug("handler added to pipeline.", metadata:["mtu_outboundOut":"\(mtu.mtuOutboundOut)", "mtu_outboundIn":"\(mtu.mtuOutboundIn)", "mtu_inboundIn":"\(mtu.mtuInboundIn)", "mtu_inboundOut":"\(mtu.mtuInboundOut)"])
	}

	internal func handlerRemoved(context:ChannelHandlerContext) {
		encodeBuffer = nil
		log.debug("handler removed from pipeline.")
	}

	internal func userInboundEventTriggered(context:ChannelHandlerContext, event:Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
}


// MARK: Read
extension KCPSegment.Handler {
	/// the error that is thrown when a kcp segment fails to parse from an inbound byte buffer
	internal struct ParseFailure:Sendable, Swift.Error {}
	/// the standard swiftnio channel read function that is called when data is read from the previous handler in the pipeline.
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let logger = log
		var encodedInbound = unwrapInboundIn(data)
		var i = 0
		while encodedInbound.associatedValue.readableBytes >= IKCP_OVERHEAD, let segment = KCPSegment(decode:&encodedInbound.buffer) {
			i += 1
			logger.trace("decoded kcp segment from byte buffer.", metadata:["public_key":"\(encodedInbound.publicKey)", "segment_sequence_number":"\(segment.header.sequenceNumber)", "segment_command":"\(segment.header.command)", "segment_data_length":"\(segment.header.dataLength)", "segment_fragment_id":"\(segment.header.fragmentID)", "segment_timestamp":"\(segment.header.timestamp)", "segment_una":"\(segment.header.una)"])
			context.fireChannelRead(wrapInboundOut(PeerAssociated<KCPSegment>(publicKey:encodedInbound.publicKey, segment:segment)))
		}
	}

	internal func channelReadComplete(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		log.trace("channel read complete.")
		context.fireChannelReadComplete()
	}
}


// MARK: Write
extension KCPSegment.Handler {
	/// the standard swiftnio channel write function that is called when data is written to the next handler in the pipeline.
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let decodedOutbound = unwrapOutboundIn(data)
		if writtenStack.stack(context:context, segment:decodedOutbound.associatedValue, for:decodedOutbound.publicKey, promise:promise, handler:self) == true {
			outboundOutCount += 1
		}
		stackedSegmentCount += 1
		log.trace("stacked kcp segment for outbound write.", metadata:["public_key":"\(decodedOutbound.publicKey)", "stacked_segments":"\(stackedSegmentCount)", "outbound_writes_since_flush":"\(outboundOutCount)"])
	}

	internal func flush(context:ChannelHandlerContext) {
		outboundOutCount = 0
		stackedSegmentCount = 0
		log.trace("flushing...")
		writtenStack.completeAll(context:context, handler:self)
		context.flush()
	}
}
