import NIO
import RAW
import RAW_dh25519
import Logging
import wireguard_crypto_core

/// A decoded KCP segment associated with a peer public key. Deprecated; use
/// `PeerAssociated<KCPSegment>` instead.
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

/// A decoded byte buffer associated with a peer public key. Deprecated; use
/// `PeerAssociated<ByteBuffer>` instead.
@available(*, deprecated, message:"use PeerAssociated<ByteBuffer> instead")
internal typealias PeerPayload = PeerAssociated<ByteBuffer>
extension PeerAssociated where AssociatedType == ByteBuffer {
	@available(*, deprecated, renamed:"associatedValue")
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
	/// Stacks multiple KCP segments into a single payload below the MTU size.
	fileprivate struct MTUStacking:Sendable {
		/// The logger used for logging within this struct.
		private let log:Logger

		private let mtu:MTULimits

		/// Stores the pending promises that were encoded into the byte buffer for each public key.
		private var promiseStack:[PublicKey:[EventLoopPromise<Void>]] = [:]
		/// Stores the byte buffers that are being built for each public key.
		private var segmentStack:[PublicKey:ByteBuffer] = [:]

		internal init(privateKey:MemoryGuarded<PrivateKey>, mtu:MTULimits, logLevel:consuming Logger.Level) {
			self.mtu = mtu
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = logLevel
			buildLogger[metadataKey:"public-key_self"] = "\(PublicKey(privateKey:privateKey))"
			log = buildLogger
			buildLogger.trace("instance initialized.", metadata:["mtu_outboundOut":"\(mtu.mtuOutboundOut)"])
		}

		/// Adds a segment to the stack for the given public key. If the segment
		/// would cause the MTU to be exceeded, the existing buffer is flushed first.
		/// - Returns: `true` if outbound data was written to the context, `false` otherwise.
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

		/// Writes the stacked KCP segments from the byte buffer, attaching the correct
		/// promises to each segment, and clears the segment and promise stacks.
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

	/// The head channel handler for KCP, which decodes inbound KCP segments from
	/// byte buffers and stacks outbound segments into MTU-sized buffers.
	public final class Handler:PeerAssociatedHeadHandler, @unchecked Sendable {

		/// The type that comes into the channel from the previous handler.
		public typealias InboundIn = PeerAssociated<ByteBuffer>
		/// The type that goes out of the channel to the next handler.
		public typealias InboundOut = PeerAssociated<KCPSegment>

		/// The type that comes into the channel from the previous writer.
		public typealias OutboundIn = PeerAssociated<KCPSegment>
		/// The type that goes out of the channel to the next writer.
		public typealias OutboundOut = PeerAssociated<ByteBuffer>

		/// The logger used for logging within this handler.
		private let log:Logger
		/// The MTU for the data payload within a KCP segment.
		private let mtu:MTULimits

		/// A buffer used for encoding segments to avoid reallocating on every write.
		private var encodeBuffer:ByteBuffer! = nil

		/// The primary tool for stacking segments into (up to) MTU-sized buffers.
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
	/// Called when the handler is added to the pipeline; allocates the encode buffer.
	public func handlerAdded(context:ChannelHandlerContext) {
		encodeBuffer = context.channel.allocator.buffer(capacity:Int(mtu.mtuOutboundOut))
		log.debug("handler added to pipeline.", metadata:["mtu_outboundOut":"\(mtu.mtuOutboundOut)", "mtu_outboundIn":"\(mtu.mtuOutboundIn)", "mtu_inboundIn":"\(mtu.mtuInboundIn)", "mtu_inboundOut":"\(mtu.mtuInboundOut)"])
	}

	/// Called when the handler is removed from the pipeline; releases the encode buffer.
	public func handlerRemoved(context:ChannelHandlerContext) {
		encodeBuffer = nil
		log.debug("handler removed from pipeline.")
	}

	/// Passes any user inbound event to the next handler in the pipeline.
	public func userInboundEventTriggered(context:ChannelHandlerContext, event:Any) {
		log.trace("user inbound event triggered. this handler is not user configurable in this way, so the passed event instance will be passed downstream...", metadata:["event_instance_type":"\(String(describing:type(of:event)))"])
		context.fireUserInboundEventTriggered(event)
	}
}


// MARK: Read
extension KCPSegment.Handler {
	/// The error thrown when a KCP segment fails to parse from an inbound byte buffer.
	internal struct ParseFailure:Sendable, Swift.Error {}
	/// Decodes and forwards each complete KCP segment from the inbound byte buffer.
	public func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let logger = log
		var encodedInbound = unwrapInboundIn(data)
		var i = 0
		while encodedInbound.associatedValue.readableBytes >= IKCP_OVERHEAD, let segment = KCPSegment(decode:&encodedInbound.buffer) {
			i += 1
			logger.trace("decoded kcp segment from byte buffer.", metadata:["public_key":"\(encodedInbound.publicKey)", "segment_sequence_number":"\(segment.header.sequenceNumber)", "segment_command":"\(segment.header.command)", "segment_data_length":"\(segment.header.dataLength)", "segment_fragment_id":"\(segment.header.fragmentID)", "segment_timestamp":"\(segment.header.timestamp)", "segment_una":"\(segment.header.una)"])
			context.fireChannelRead(wrapInboundOut(PeerAssociated<KCPSegment>(publicKey:encodedInbound.publicKey, segment:segment)))
		}
	}

	/// Called when a channel read completes; forwards the event downstream.
	public func channelReadComplete(context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		log.trace("channel read complete.")
		context.fireChannelReadComplete()
	}
}


// MARK: Write
extension KCPSegment.Handler {
	/// Stacks the outbound KCP segment into the MTU-sized write buffer.
	public func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		let decodedOutbound = unwrapOutboundIn(data)
		if writtenStack.stack(context:context, segment:decodedOutbound.associatedValue, for:decodedOutbound.publicKey, promise:promise, handler:self) == true {
			outboundOutCount += 1
		}
		stackedSegmentCount += 1
		log.trace("stacked kcp segment for outbound write.", metadata:["public_key":"\(decodedOutbound.publicKey)", "stacked_segments":"\(stackedSegmentCount)", "outbound_writes_since_flush":"\(outboundOutCount)"])
	}

	/// Flushes all stacked outbound segments to the next handler in the pipeline.
	public func flush(context:ChannelHandlerContext) {
		outboundOutCount = 0
		stackedSegmentCount = 0
		log.trace("flushing...")
		writtenStack.completeAll(context:context, handler:self)
		context.flush()
	}
}
