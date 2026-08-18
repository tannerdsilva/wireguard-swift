import NIO
import struct RAW_dh25519.PublicKey
import Logging
import RAW

public enum SendError:Swift.Error {
	case mssValueError
	case inputLengthError
	case invalidDataCountForSendWindow
}

public enum ReceiveError:Swift.Error {
	case receiveQueueEmpty
	case lengthTooSmall
	case missingFirstElement
	case firstSegmentFragmentError
}

public enum InputError:Swift.Error {
	case invalidInputCount
	case convValueMismatch
	case partialTrailingData
	case invalidCMD
}

internal func iclock(_ time:NIODeadline) -> UInt64 {
	let now = time.uptimeNanoseconds
	return UInt64(now / 1_000_000) // nanoseconds → milliseconds
}
@inline(__always) private func ibound(_ lower: UInt64, _ value: UInt64, _ upper: UInt64) -> UInt64 {
	return min(max(value, lower), upper)
}
@inline(__always) private func itimeDiff(later a:UInt64, earlier b:UInt64) -> Int64 {
	return Int64(bitPattern: a &- b)
}

let IKCP_RTO_MIN:UInt64 = 100
let IKCP_RTO_DEF:UInt64 = 200
let IKCP_RTO_MAX:UInt64 = 60000

let IKCP_CMD_PUSH:UInt8 = 81
let IKCP_CMD_ACK:UInt8 = 82
let IKCP_CMD_WASK:UInt8 = 83
let IKCP_CMD_WINS:UInt8 = 84
let IKCP_CMD_KILL:UInt8 = 85

let IKCP_WND_RCV:UInt32 = 256
let IKCP_OVERHEAD:UInt32 = 24
/*

LAW OF THE LAND

=================

nodelay = 1 ALWAYS. this is not a param but a hard coded reality of the architecture of this project.
nocwnd NEVER. there WILL be a congestion window under ALL circumstances.

*/

extension KCPControlBlock {
	/// thrown when a kcp control block reaches a dead link state.
	internal struct DeadlinkError:Swift.Error {}
}

internal struct KCPControlBlock {
	/// the public key of the peer this control block is associated with
	internal let peerPublicKey:PublicKey
	
	/// the context of the channel this control block is associated with
	internal let log:Logger

	/// conversation id.
	internal let conv:UInt16
	
	/// maximum transmission unit: the largest udp packet accepted
	internal var mtu:UInt32 {
		get {
			return mss + IKCP_OVERHEAD
		}
	}
	
	/// maximum segment size: largest amount of data per segment
	internal let mss:UInt32
	
	/// - *purpose*: oldest unacknowledged sequence number
	/// - *read/written when*: written when an ack is received, read when sending data
	/// - *how it affects ack processing*: any segments with a sequence number less than snd_una can be removed from the send buffer
	internal var snd_una:UInt32 = 0

	/// - *purpose*: next sequence number to use for a fresh data segment
	/// - *read/written when*: written when a new segment is sent.
	/// - *how it affects ack processing*: determines the sn in the outgoing segment header. the peer will ack this value
	internal var snd_nxt:UInt32 = 0

	/// - *purpose*: next expected sequence number from the peer.
	/// - *read/written when*: written when an in-order segment is delivered to the application.
	/// - *how it affects ack processing*: any segment with `sn == rcv_nxt` will be acked immediately, out of order segments will be stored in `rcv_buf` to close the gap
	internal var rcv_nxt:UInt32 = 0

	/// - *purpose*: most recent remote timestamp (from the last ack received)
	/// - *read/written when*: written for every inbound segment, `ts_recent = seg.ts`
	/// - *how it affects ack processing*: used together with the ack timestamp (`seg.ts`) to calculate the RTT (now - seg.ts)
	internal var ts_recent:UInt32 = 0

	/// - *purpose*: timestamp of the last ack received
	/// - *read/written when*: written when we flush our acklist.
	/// - *how it affects ack processing*: allows the peer to compute its RTT; also used for delayed‑ACK heuristics.
	internal var ts_lastack:UInt32 = 0
	
	/// used to track the round trip time and retransmission information for this control block
	internal var rttInfo:RoundTripTimeInfo = RoundTripTimeInfo()

	/// used to track the window-probe state for this control block
	internal var probeInfo:ProbeInfo = ProbeInfo()

	// buffers
	/// the buffer for data that is being transmitted to the remote peer.
	/// - NOTE: previously known as `send_buf`
	internal var outboundInBuffer = LinkedList<(data:KCPSegment, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?)>()		// user data waiting to be segmented and sent out
	
	/// a structure used to encompass all the info involved with firing data to inbound out.
	internal struct InboundOutInfo:Sendable {
		/// boolean flag to indicate if the buffer should be cleared on next use
		internal var inboundOutByteByfferClearOnNextUse = false

		/// the buffer that will eventually make up a complete message that gets passed to inbound out
		internal var inboundOutByteBuffer:ByteBuffer
	}
	/// the info associated with the inbound out buffer.
	/// - NOTE: previously known as `rcv_buf`
	internal var inboundOutInfo:InboundOutInfo
	
	/// segments that are waiting to be assembled in the correct order.
	/// - NOTE: previously known as `rcv_queue`
	internal var inboundInBuffer = LinkedList<KCPSegment>()

	/// counts the number of kcp segments that were written to the outboundInBuffer for each cycle of reading. used at `channelReadComplete` to determine if a flush is needed
	internal var outboundOutSegmentsWrittenSinceChannelReadComplete:Int = 0
	
	/// Signal that this block has control blocks waiting for it to finish
	public var isStalling:Bool = false
	
	/// info on whether the kcpcb has seen recent activity. Can only becomes false when a probe is received.
	public var isInactive:Bool = false
	
	/// info on whether this control block is the active receiver. kcpcb can only write inboundOut if it's the active receiver
	public var isActiveReceiver = false

	// window stuff
	internal var writeWindow:UInt32
	internal var readWindow:UInt32
	internal var remoteWindow:UInt32
	internal var flightBytes:UInt32 = 0
	
	internal var storedSendingGenesis:UInt64 = 0
	internal var lastGenesis:UInt64 = 0

	internal init(context:ChannelHandlerContext, peerPublicKey:PublicKey, conv:UInt16, mss:Int, writeWindow:UInt32, readWindow:UInt32, rmt_wnd:UInt32 = IKCP_WND_RCV, logLevel:Logger.Level) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		buildLogger[metadataKey: "public-key_peer"] = "\(peerPublicKey)"
		buildLogger[metadataKey: "conversation_id"] = "\(conv)"
		self.log = buildLogger
		self.peerPublicKey = peerPublicKey
		self.inboundOutInfo = InboundOutInfo(inboundOutByteBuffer:context.channel.allocator.buffer(capacity:mss))
		self.conv = conv
		self.mss = UInt32(mss)
		self.writeWindow = writeWindow
		self.readWindow = readWindow
		self.remoteWindow = rmt_wnd
	}

	@discardableResult
	internal mutating func handleChannelRead(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, associatedSegment:PeerAssociated<KCPSegment>, now:NIODeadline, congestionWindow:inout Int, maxCongestionWindow:inout Int, writeCounter:inout Int) throws -> Bool {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		guard conv == associatedSegment.associatedValue.header.conversationID else {
			fatalError("conversation id mismatch. expected \(conv), got \(associatedSegment.associatedValue.header.conversationID). \(#file):\(#line)")
		}
		#endif
		guard associatedSegment.publicKey == peerPublicKey else {
			fatalError("internal logic error: associated segment public key does not match control block public key. \(#file):\(#line)")
		}
		var logger = log
		logger[metadataKey:"_func"] = "\(#function)"
		let now = iclock(now)
		guard associatedSegment.associatedValue.data.count == associatedSegment.associatedValue.header.dataLength else {
			throw InputError.partialTrailingData
		}
		logger.trace("handling inbound kcp segment.", metadata:["segment_sn":"\(associatedSegment.associatedValue.header.sequenceNumber)", "data_length":"\(associatedSegment.associatedValue.data.count)"])
		parseInbound(una:associatedSegment.associatedValue.header.una)
		if(associatedSegment.associatedValue.header.receiveWindowSize != 0) {
			maxCongestionWindow = min(maxCongestionWindow, Int(associatedSegment.associatedValue.header.receiveWindowSize) * Int(mtu))
		}

		switch associatedSegment.associatedValue.header.command {
			case KCPSegment.Command.ack:
				if (itimeDiff(later:now, earlier:associatedSegment.associatedValue.header.timestamp) >= 0) {
					updateInbound(rtt:now &- associatedSegment.associatedValue.header.timestamp)
				}
				parseInbound(ack: associatedSegment.associatedValue.header.sequenceNumber)
				
				// Update congestion window. Logarithmic growth
				congestionWindow += maxCongestionWindow / congestionWindow
			case KCPSegment.Command.genesis:
				let ackSeg = KCPSegment(header:KCPSegment.Header(conv:conv, cmd:.ack, rcv_wnd_size:UInt16(readWindow/mtu), frg:0, sn:associatedSegment.associatedValue.header.sequenceNumber, ts:iclock(NIODeadline.now()), una:rcv_nxt, len:0), data:ByteBufferView())
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:associatedSegment.publicKey, associatedValue:ackSeg)), promise: nil)
				writeCounter += 1
				if Int32(bitPattern:associatedSegment.associatedValue.header.sequenceNumber &- rcv_nxt) >= 0 {
					parseInbound(data: associatedSegment.associatedValue, handler:handler, context: context)
					lastGenesis = associatedSegment.associatedValue.header.timestamp
				} else if associatedSegment.associatedValue.header.timestamp != lastGenesis {
					return true
				}
			case KCPSegment.Command.push:
				// write the acknowledgement instead of pushing it to the acklist
				let ackSeg = KCPSegment(header:KCPSegment.Header(conv:conv, cmd:.ack, rcv_wnd_size:UInt16(readWindow/mtu), frg:0, sn:associatedSegment.associatedValue.header.sequenceNumber, ts:associatedSegment.associatedValue.header.timestamp, una:rcv_nxt, len:0), data:ByteBufferView())
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:associatedSegment.publicKey, associatedValue:ackSeg)), promise: nil)
				writeCounter += 1
				if Int32(bitPattern:associatedSegment.associatedValue.header.sequenceNumber &- rcv_nxt) >= 0 {
					parseInbound(data: associatedSegment.associatedValue, handler:handler, context: context)
				}
			case KCPSegment.Command.probeRequest:
				let ackResponseSeg = KCPSegment(header:KCPSegment.Header(conv:conv, cmd:.probeResponse, rcv_wnd_size:UInt16(readWindow/mtu), frg:0, sn:0, ts:0, una:rcv_nxt, len:0), data:ByteBufferView())
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:associatedSegment.publicKey, associatedValue:ackResponseSeg)), promise:nil)
				writeCounter += 1
				outboundOutSegmentsWrittenSinceChannelReadComplete += 1
				// Check inactivity
				if(associatedSegment.associatedValue.header.timestamp == 0 && inboundInBuffer.isEmpty && outboundInBuffer.isEmpty && isStalling) {
					isInactive = true
				}
			case KCPSegment.Command.probeResponse:
				// Nothing to do
				break
			case KCPSegment.Command.probeKill:
				isInactive = true
		}
		return false
	}
}

// parse data, ack, una.
// MARK: Parse Inbound
extension KCPControlBlock {
	/// Called for `.push` and `.genesis` segments only.
	/// Parses inbound data segment from a handler with its context
	/// Discards duplicate segments.
	/// Attempts to writeAllInboundOut after every parse of a data segment.
	@discardableResult
	private mutating func parseInbound(data segment:KCPSegment, handler:KCPControlBlock.Handler, context:ChannelHandlerContext) -> Bool {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		let sn = segment.header.sequenceNumber
		var isDuplicate = false
		var insertAfterNode:LinkedList<KCPSegment>.Node? = nil
		segLoop: for (curNode, seg) in inboundInBuffer.makeReverseIterator() {
			guard seg.header.sequenceNumber != sn else {
				isDuplicate = true
				break segLoop
			}
			guard Int32(bitPattern:sn &- seg.header.sequenceNumber) <= 0 else {
				insertAfterNode = curNode
				break segLoop
			}
		}

		// duplicate packets shall not be processed
		if isDuplicate == false {
			if let anchor = insertAfterNode {
				inboundInBuffer.insert(segment, after:anchor)
			} else {
				inboundInBuffer.add(segment)
			}
		}
		
		writeAllInboundOut(handler: handler, context: context)
		return isDuplicate
	}
	
	/// Attaches any in-order, continuous segments from the inbound segment buffer to an inbount out byte buffer.
	/// The byte buffer grows as segments attach to the end of the buffer.
	/// Once a fragmentID of 0 is found, we write the completed message to the next handler.
	///
	/// Use a clear byte buffer flag to determine if a message was written. If it was writte, then clear the buffer before building a new one.
	public mutating func writeAllInboundOut(handler:KCPControlBlock.Handler, context:ChannelHandlerContext) {
		while let firstNode = inboundInBuffer.front, firstNode.value!.header.sequenceNumber == rcv_nxt, isActiveReceiver  {
			inboundInBuffer.remove(firstNode)

			if inboundOutInfo.inboundOutByteByfferClearOnNextUse == true {
				inboundOutInfo.inboundOutByteBuffer.clear()
				inboundOutInfo.inboundOutByteByfferClearOnNextUse = false
			}

			inboundOutInfo.inboundOutByteBuffer.writeBytes(firstNode.value!.data)
			
			if firstNode.value!.header.fragmentID == 0 {
				context.fireChannelRead(handler.wrapInboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:inboundOutInfo.inboundOutByteBuffer)))
				inboundOutInfo.inboundOutByteByfferClearOnNextUse = true
			}

			rcv_nxt &+= 1
		}
	}

	/// Called for all segments.
	/// Removes any sent segments with a sequence number lower than una.
	private mutating func parseInbound(una:UInt32) {
		for (node, seg) in outboundInBuffer.makeIterator() {
			guard Int32(bitPattern: una &- seg.data.header.sequenceNumber) > 0 else {
				snd_una = seg.data.header.sequenceNumber
				return
			}
			node.value!.ackPromise?.succeed()
			outboundInBuffer.remove(node)
		}
		snd_una = snd_nxt
	}

	/// Called for `.ack` segments only.
	private mutating func parseInbound(ack sn:UInt32) {
		guard Int32(bitPattern:sn &- snd_una) >= 0 && Int32(bitPattern:sn &- snd_nxt) < 0 else {
			return
		}
		defer {
			if let node = outboundInBuffer.front {
				snd_una = node.value!.data.header.sequenceNumber
			} else {
				snd_una = snd_nxt
			}
		}
		segLoop: for (curNode, seg) in outboundInBuffer.makeIterator() {
			guard seg.data.header.sequenceNumber != sn else {
				curNode.value!.ackPromise?.succeed()
				outboundInBuffer.remove(curNode)
				break segLoop
			}
			guard Int32(bitPattern:sn &- seg.data.header.sequenceNumber) >= 0 else {
				break segLoop
			}
		}
	}

	/// Updates stored rtt values for the control block using the segments rtt.
	/// Uses the same rtt calculations as TCP
	private mutating func updateInbound(rtt: UInt64) {
		if rttInfo.rx_srtt == 0 {
			rttInfo.rx_srtt = rtt
			rttInfo.rx_rttval = rtt / 2
		} else {
			var delta = Int64(rtt) - Int64(rttInfo.rx_srtt)
			if delta < 0 {
				delta = -delta
			}
			rttInfo.rx_rttval = ((3 * rttInfo.rx_rttval + UInt64(delta)) / 4)
			rttInfo.rx_srtt = (7 * rttInfo.rx_srtt + rtt) / 8
			if rttInfo.rx_srtt < 1 {
				rttInfo.rx_srtt = 1
			}
		}
		// calculate the retransmission time
		let rtoUnbound:UInt64 = rttInfo.rx_srtt + 4 * rttInfo.rx_rttval
		rttInfo.rx_rto = ibound(rttInfo.rx_minrto, rtoUnbound, rttInfo.rx_maxrto)
	}
}

// MARK: Sending
extension KCPControlBlock {
	public mutating func handleWrite(context:borrowing ChannelHandlerContext, handler:borrowing KCPControlBlock.Handler, message:ByteBuffer, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?, isGenesis:Bool) {
		let count = (message.readableBytes + Int(mss) - 1) / Int(mss)
		for offset in stride(from: 0, to: message.readableBytes, by: Int(mss)) {
			let fragSize = min(Int(mss), message.readableBytes - offset)
			let view = message.getSlice(at: message.readerIndex + offset, length: fragSize)
			let command = offset == 0 ? (isGenesis ? KCPSegment.Command.genesis : KCPSegment.Command.push) : KCPSegment.Command.push
			if isGenesis {
				if let rnd = try? generateSecureRandomBytes(count: 8) {
					storedSendingGenesis = rnd.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
				} else {
					storedSendingGenesis = UInt64.random(in: UInt64.min...UInt64.max)
				}
			}
			let header = KCPSegment.Header(conv: conv, cmd: command, rcv_wnd_size:UInt16(readWindow/mtu), frg: UInt8(count - offset/Int(mss) - 1), sn: snd_nxt, ts:0, una:0, len: UInt16(fragSize))
			snd_nxt &+= 1
			let seg = KCPSegment(header: header, data: view!.readableBytesView)
			
			if (offset/Int(mss) == count-1) {
				outboundInBuffer.addTail((seg, writePromise, ackPromise))
			} else {
				outboundInBuffer.addTail((seg, nil, nil))
			}
		}
		isInactive = false
	}

	// KCP Flush
	// - Sends any pending ACKs
	// - Sends any pending Probes
	// - Sends any pending data packets that can be sent
	@available(*, noasync)
	public mutating func resendAndProbe(context:ChannelHandlerContext, handler:KCPControlBlock.Handler, now:NIODeadline, congestionWindow:inout Int, minCongestionWindow:Int, writerCount:inout Int) {
		let now = iclock(now)
		
		var resend = false
		var resendCount = 0
		var count = 0
		for (node, seg) in outboundInBuffer.makeIterator() {
			defer {
				count += Int(seg.data.header.dataLength)
			}
			if(count > congestionWindow) {
				break
			}
			// Sending segments the first time
			if(seg.data.runtimeMetadata.xmit == 0) {
				node.value!.data.runtimeMetadata.xmit = 1
				node.value!.data.runtimeMetadata.rto = rttInfo.rx_rto
				node.value!.data.runtimeMetadata.resendts = now &+ node.value!.data.runtimeMetadata.rto
				node.value!.data.header.timestamp = node.value!.data.header.command == .genesis ? storedSendingGenesis : now
				node.value!.data.header.una = rcv_nxt
				log.trace("writing kcp segment to next handler in pipeline.", metadata:["public-key_remote":"\(peerPublicKey)", "segment_sequence_number":"\(node.value!.data.header.sequenceNumber)", "segment_command":"\(node.value!.data.header.command)", "segment_data_length":"\(node.value!.data.header.dataLength)", "segment_fragment_id":"\(node.value!.data.header.fragmentID)", "segment_timestamp":"\(node.value!.data.header.timestamp)", "segment_una":"\(node.value!.data.header.una)"])
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:node.value!.data)), promise:node.value!.writePromise)
				writerCount &+= 1
				flightBytes &+= UInt32(seg.data.header.dataLength)
			}
			// Resending segments if enough time has passed
			else if itimeDiff(later:now, earlier:seg.data.runtimeMetadata.resendts) >= 0 {
				resend = true
				node.value!.data.runtimeMetadata.xmit &+= 1
				resendCount = Int(seg.data.runtimeMetadata.xmit)
				node.value!.data.runtimeMetadata.rto = node.value!.data.runtimeMetadata.rto &+ (node.value!.data.runtimeMetadata.rto / 2)
				node.value!.data.runtimeMetadata.resendts = now &+ node.value!.data.runtimeMetadata.rto
				node.value!.data.header.timestamp = node.value!.data.header.command == .genesis ? storedSendingGenesis : now
				node.value!.data.header.una = rcv_nxt
				log.trace("writing kcp segment to next handler in pipeline.", metadata:["public-key_remote":"\(peerPublicKey)", "segment_sequence_number":"\(node.value!.data.header.sequenceNumber)", "segment_command":"\(node.value!.data.header.command)", "segment_data_length":"\(node.value!.data.header.dataLength)", "segment_fragment_id":"\(node.value!.data.header.fragmentID)", "segment_timestamp":"\(node.value!.data.header.timestamp)", "segment_una":"\(node.value!.data.header.una)"])
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:node.value!.data)), promise:node.value!.writePromise)
				writerCount &+= 1
			}
		}
		// If resent at all, need to shorten congestion window
		if(resend) {
			congestionWindow = max(minCongestionWindow, congestionWindow - 1 * Int(mtu))
			log.trace("Shrinking congestion window", metadata:["newWindowSize":"\(congestionWindow)"])
		}
		// The higher the number of resends, the faster cwnd decreases
		//congestionWindow = max(minCongestionWindow, congestionWindow * (10 - resendCount) / 10)
		
		// Send probe with ts being the send buffer count
		if itimeDiff(later:now, earlier:probeInfo.ts_probe) >= 0 {
			probeInfo.probe_wait = 500
			probeInfo.ts_probe = now + probeInfo.probe_wait
			context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:KCPSegment(header:KCPSegment.Header(conv:conv, cmd:.probeRequest, rcv_wnd_size:UInt16(readWindow/mtu), frg:0, sn:snd_nxt, ts:UInt64(outboundInBuffer.count), una:rcv_nxt, len:0), data:ByteBufferView()))), promise:nil)
			log.trace("writing probe request")
		}
	}
}
