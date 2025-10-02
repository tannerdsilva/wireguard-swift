import NIO
import struct RAW_dh25519.PublicKey
import Logging

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

public func iclock(_ delay:UInt64 = 0) -> UInt32 {
	let now = NIODeadline.now().uptimeNanoseconds - delay
	return UInt32(now / 1_000_000) // nanoseconds → milliseconds
}
@inline(__always) private func imax(_ a: UInt32, _ b: UInt32) -> UInt32 {
	return a > b ? a : b
}
@inline(__always) private func ibound(_ lower: UInt32, _ value: UInt32, _ upper: UInt32) -> UInt32 {
	return min(max(value, lower), upper)
}
@inline(__always) private func itimeDiff(later a:UInt32, earlier b:UInt32) -> Int32 {
return Int32(bitPattern: a &- b)
}

let IKCP_RTO_NDL:UInt32 = 30
let IKCP_RTO_MIN:UInt32 = 100
let IKCP_RTO_DEF:UInt32 = 200
let IKCP_RTO_MAX:UInt32 = 60000
let IKCP_CMD_PUSH:UInt8 = 81
let IKCP_CMD_ACK:UInt8 = 82
let IKCP_CMD_WASK:UInt8 = 83
let IKCP_CMD_WINS:UInt8 = 84
let IKCP_ASK_SEND:UInt32 = 1
let IKCP_ASK_TELL:UInt32 = 2
let IKCP_WND_SND:UInt32 = 256
let IKCP_WND_RCV:UInt32 = 256
let IKCP_OVERHEAD:UInt32 = 24
let IKCP_DEADLINK:UInt32 = 20
let IKCP_THRESH_INIT:UInt32 = 2
let IKCP_THRESH_MIN:UInt32 = 2
let IKCP_PROBE_INIT:UInt32 = 7000
let IKCP_PROBE_LIMIT:UInt32 = 120000


/*

LAW OF THE LAND

=================

nodelay = 1 ALWAYS. this is not a param but a hard coded reality of the architecture of this project.
nocwnd = 0 ALWAYS. there will be a congestion window under all circumstances.

*/

extension KCPControlBlock {
	@available(*, deprecated, renamed: "outboundOutBuffer")
	internal var sendBuffer:LinkedList<(data:KCPSegment, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?)> {
		get {
			return outboundOutBuffer
		}
	}

	internal var receiveBuffer:LinkedList<KCPSegment> {
		get {
			return receiveBuffer
		}
	}
}

extension KCPControlBlock {
	internal struct DeadlinkError:Swift.Error {}
}

internal final class KCPControlBlock {
	/// the public key of the peer this control block is associated with
	internal let peerPublicKey:PublicKey
	/// the context of the channel this control block is associated with
	internal let log:Logger

	/// conversation id.
	internal let conv:UInt32
	/// maximum transmission unit: the largest udp packet accepted
	internal let mtu:UInt32
	/// maximum segment size: largest amount of data per segment
	internal var mss:UInt32 {
		get {
			return mtu - IKCP_OVERHEAD
		}
	}
	
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
	/// used to track the congestion window state for this control block
	internal var cwndInfo:CongestionWindowInfo = CongestionWindowInfo()


	/// used to track the window-probe state for this control block
	internal var probeInfo:ProbeInfo = ProbeInfo()

	// buffers
	/// the buffer for data that is being transmitted to the remote peer.
	/// - NOTE: previously known as `send_buf`
	internal var outboundOutBuffer = LinkedList<(data:KCPSegment, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?)>()		// user data waiting to be segmented and sent out
	
	/// a structure used to encompass all the info involved with firing data to inbound out.
	internal struct InboundOutInfo:Sendable {
		/// boolean flag to indicate if the buffer should be cleared on next use
		internal var inboundOutByteByfferClearOnNextUse = false
		/// counts the number of kcp segments that were written to the inboundOutByteBuffer
		internal var inboundOutByteBufferSegmentsWritten:Int = 0
		/// the buffer that will eventually make up a complete message that gets passed to inbound out
		internal var inboundOutByteBuffer:ByteBuffer
	}
	/// the info associated with the inbound out buffer.
	internal var inboundOutInfo:InboundOutInfo
	
	/// segments that are waiting to be assembled in the correct order
	internal var inboundInBuffer = LinkedList<KCPSegment>()

	/// counts the number of kcp segments that were written to the outboundOutBuffer for each cycle of reading. used at `channelReadComplete` to determine if a flush is needed
	internal var outboundOutSegmentsWrittenSinceChannelReadComplete:Int = 0

	// window stuff
	internal let snd_wnd:UInt32
	internal let rcv_wnd:UInt32
	internal let rmt_wnd:UInt32

	internal init(context:ChannelHandlerContext, peerPublicKey:PublicKey, conv:UInt32, mtu:UInt32, snd_wnd:UInt32 = IKCP_WND_SND, rcv_wnd:UInt32 = IKCP_WND_RCV, rmt_wnd:UInt32 = IKCP_WND_RCV, logLevel:Logger.Level) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		self.log = buildLogger
		self.peerPublicKey = peerPublicKey
		self.inboundOutInfo = InboundOutInfo(inboundOutByteBuffer:context.channel.allocator.buffer(capacity:Int(mtu * snd_wnd)))
		self.conv = conv
		self.mtu = mtu
		self.snd_wnd = snd_wnd
		self.rcv_wnd = rcv_wnd
		self.rmt_wnd = rmt_wnd
	}

	internal func handleChannelReadComplete(context:ChannelHandlerContext, handler:KcpControlBlockHandler) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		
		if outboundOutSegmentsWrittenSinceChannelReadComplete > 0 {
			context.flush()
			outboundOutSegmentsWrittenSinceChannelReadComplete = 0
		}
	}

	internal func handleChannelRead(context:ChannelHandlerContext, handler:KcpControlBlockHandler, associatedSegment:PeerAssociated<KCPSegment>) throws {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		
		let now = iclock()
		let previousUna = snd_una

		guard conv == associatedSegment.associatedValue.header.conversationID else {
			throw InputError.convValueMismatch
		}
		guard associatedSegment.associatedValue.data.count == associatedSegment.associatedValue.header.dataLength else {
			throw InputError.partialTrailingData
		}

		parseInbound(una:associatedSegment.associatedValue.header.una)

		switch associatedSegment.associatedValue.header.command {
			case KCPSegment.Command.ack:
				if (itimeDiff(later:now, earlier:associatedSegment.associatedValue.header.timestamp) >= 0) {
					updateInbound(rtt:now &- associatedSegment.associatedValue.header.timestamp)
				}
				parseInbound(ack: associatedSegment.associatedValue.header.sequenceNumber)
			case KCPSegment.Command.push:
				if Int32(bitPattern:associatedSegment.associatedValue.header.sequenceNumber &- (rcv_nxt + rcv_wnd)) < 0 {
					
					// write the acknowledgement instead of pushing it to the acklist
					let ackSeg = KCPSegment(header:KCPSegment.Header(conv:conv, cmd:.ack, rcv_wnd_size:wndUnused(), frg:0, sn:associatedSegment.associatedValue.header.sequenceNumber, ts:associatedSegment.associatedValue.header.timestamp, una:rcv_nxt, len:0), data:ByteBufferView())
					context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:associatedSegment.publicKey, associatedValue:ackSeg)), promise: nil)
					outboundOutSegmentsWrittenSinceChannelReadComplete += 1
					
					if Int32(bitPattern:associatedSegment.associatedValue.header.sequenceNumber &- rcv_nxt) >= 0 {
						parseInbound(data: associatedSegment.associatedValue, handler:handler, context: context)
					}
				}
			case KCPSegment.Command.probeRequest:
				let ackResponseSeg = KCPSegment(header:KCPSegment.Header(conv:conv, cmd:.probeResponse, rcv_wnd_size:wndUnused(), frg:0, sn:0, ts:0, una:rcv_nxt, len:0), data:ByteBufferView())
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:associatedSegment.publicKey, associatedValue:ackResponseSeg)), promise:nil)
				outboundOutSegmentsWrittenSinceChannelReadComplete += 1
			case KCPSegment.Command.probeResponse:
				// nothing to do here
			break;
		}

		if itimeDiff(later:snd_una, earlier:previousUna) > 0 {
			if cwndInfo.cwnd < rmt_wnd {
				let mss = self.mss
				if cwndInfo.cwnd < cwndInfo.ssthresh {
					cwndInfo.cwnd &+= 1
					cwndInfo.incr &+= mss
				} else {
					if cwndInfo.incr < mss {
						cwndInfo.incr = mss
					}
					cwndInfo.incr &+= (mss * mss) / cwndInfo.incr + (mss / 16)
					if ((cwndInfo.cwnd &+ 1) &* mss <= cwndInfo.incr) {
						cwndInfo.cwnd = (cwndInfo.incr &+ mss &- 1) / (mss > 0 ? mss : 1)
					}
				}

				if cwndInfo.cwnd > rmt_wnd {
					cwndInfo.cwnd = rmt_wnd
					cwndInfo.incr = rmt_wnd &* mss
				}
			}
		}
	}
}

// MARK: Parse Inbound
extension KCPControlBlock {
	/// parse inbound data segment from a handler with its context
	/// - returns: the number of messages fired to the next pipeline reader
	private func parseInbound(data segment:KCPSegment, handler:KcpControlBlockHandler, context:ChannelHandlerContext) {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		let sn = segment.header.sequenceNumber
		var isDuplicate = false
		var insertAfterNode:LinkedList<KCPSegment>.Node? = nil
		segLoop: for (curNode, seg) in receiveBuffer.makeReverseIterator() {
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

		// loop through any continuous segments in the receive buffer and write them to the outbound out byte buffer
		while let firstNode = inboundInBuffer.front, firstNode.value!.header.sequenceNumber == rcv_nxt && inboundOutInfo.inboundOutByteBufferSegmentsWritten < rcv_wnd {
			// remove the node from the receive buffer and add it to the receive queue
			// start by popping it from the receive buffer
			inboundInBuffer.remove(firstNode)

			// if the inboundOutByteBuffer is marked to be cleared on next use, clear it now
			if inboundOutInfo.inboundOutByteByfferClearOnNextUse == true {
				inboundOutInfo.inboundOutByteBuffer.clear()
				inboundOutInfo.inboundOutByteBufferSegmentsWritten = 0
				inboundOutInfo.inboundOutByteByfferClearOnNextUse = false
			}

			// write the segment contents to the inboundOutByteBuffer
			inboundOutInfo.inboundOutByteBuffer.writeBytes(firstNode.value!.data)
			inboundOutInfo.inboundOutByteBufferSegmentsWritten += 1

			// if this is the last fragment of a message, fire the entire inboundOutByteBuffer to the pipeline and mark it to be cleared on next reader in the pipeline
			if firstNode.value!.header.fragmentID == 0 {
				context.fireChannelRead(handler.wrapInboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:inboundOutInfo.inboundOutByteBuffer)))
				inboundOutInfo.inboundOutByteByfferClearOnNextUse = true
			}

			// increment rcv_nxt to expect the next segment
			rcv_nxt &+= 1
		}
	}

	/// parse inbound una data
	private func parseInbound(una:UInt32) {
		for (node, seg) in outboundOutBuffer.makeIterator() {
			// guard isAcked == true
			guard Int32(bitPattern: una &- seg.data.header.sequenceNumber) > 0 else {
				snd_una = seg.data.header.sequenceNumber
				return
			}
			node.value!.ackPromise?.succeed()
			outboundOutBuffer.remove(node)
		}
		snd_una = snd_nxt
	}

	/// parse inbound ack data
	private func parseInbound(ack sn:UInt32) {
		guard Int32(bitPattern:sn &- snd_una) >= 0 && Int32(bitPattern:sn &- snd_nxt) < 0 else {
			return
		}
		defer {
			if let node = outboundOutBuffer.front {
				snd_una = node.value!.data.header.sequenceNumber
			} else {
				snd_una = snd_nxt
			}
		}
		segLoop: for (curNode, seg) in outboundOutBuffer.makeIterator() {
			guard seg.data.header.sequenceNumber != sn else {
				curNode.value!.ackPromise?.succeed()
				outboundOutBuffer.remove(curNode)
				break segLoop
			}
			guard Int32(bitPattern:sn &- seg.data.header.sequenceNumber) >= 0 else {
				break segLoop
			}
		}
	}

	private func updateInbound(rtt: UInt32) {
		if rttInfo.rx_srtt == 0 {
			rttInfo.rx_srtt = rtt
			rttInfo.rx_rttval = rtt / 2
		} else {
			var delta = Int32(rtt) - Int32(rttInfo.rx_srtt)
			if delta < 0 {
				delta = -delta
			}
			rttInfo.rx_rttval = ((3 * rttInfo.rx_rttval + UInt32(delta)) / 4)
			rttInfo.rx_srtt = (7 * rttInfo.rx_srtt + rtt) / 8
			if rttInfo.rx_srtt < 1 {
				rttInfo.rx_srtt = 1
			}
		}
		// calculate the retransmission time
		let rtoUnbound:UInt32 = rttInfo.rx_srtt + 4 * rttInfo.rx_rttval
		rttInfo.rx_rto = ibound(rttInfo.rx_minrto, rtoUnbound, rttInfo.rx_maxrto)
	}
}

extension KCPControlBlock {
	public func send(_ inputBuffer: ByteBuffer, writePromise: EventLoopPromise<Void>? = nil, ackPromise: EventLoopPromise<Void>? = nil) -> Bool {
		let count = (inputBuffer.readableBytes + Int(mss) - 1) / Int(mss)
		var bufferIsFull = false
		if (UInt32(count) + sendBuffer.count < snd_wnd ) {
			bufferIsFull = true
		}

		var i = 0
		for offset in stride(from: 0, to: inputBuffer.readableBytes, by: Int(mss)) {
			let fragSize = min(Int(mss), inputBuffer.readableBytes - offset)
			
			let view = inputBuffer.getSlice(at: inputBuffer.readerIndex + offset, length: fragSize)

			let header = KCPSegment.Header(conv: conv, cmd: .push, frg: UInt8(count - i - 1), sn: snd_nxt, len: UInt32(fragSize))
			snd_nxt &+= 1
			let seg = KCPSegment(header: header, data: view!.readableBytesView)
			
			if (i == count-1) {
				sendBuffer.addTail((seg, writePromise, ackPromise))
			} else {
				sendBuffer.addTail((seg, nil, nil))
			}
			
			i += 1
		}
		return bufferIsFull
	}

	private func wndUnused() -> UInt16 {
		if (receiveQueue.count < rcv_wnd) {
			return UInt16(rcv_wnd - receiveQueue.count)
		}
		return 0
	}

	// KCP Flush
	// - Sends any pending ACKs
	// - Sends any pending Probes
	// - Sends any pending data packets that can be sent
	@available(*, noasync)
	public func getOutboundSegments(context:ChannelHandlerContext, handler:KcpControlBlockHandler) -> [(KCPSegment, EventLoopPromise<Void>?)]{	
		let now = iclock()

		// only manage probes if we have nothing to send
		if rmt_wnd == 0 || outboundOutBuffer.count == 0 {
			// Update probe time variables and prepare send ask_probe if needed
			if probeInfo.probe_wait == 0 {
				probeInfo.probe_wait = IKCP_PROBE_INIT
			} else if itimeDiff(later:now, earlier:probeInfo.ts_probe) >= 0 {
				if probeInfo.probe_wait < IKCP_PROBE_INIT {
					probeInfo.probe_wait = IKCP_PROBE_INIT
				}
				probeInfo.probe_wait += probeInfo.probe_wait / 2
				if probeInfo.probe_wait > IKCP_PROBE_LIMIT {
					probeInfo.probe_wait = IKCP_PROBE_LIMIT
				}
				probeInfo.ts_probe = now + probeInfo.probe_wait
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:KCPSegment(header:KCPSegment.Header(conv:conv, cmd:.probeRequest, rcv_wnd_size:wndUnused(), frg:0, sn:0, ts:0, una:rcv_nxt, len:0), data:ByteBufferView()))), promise:nil)
			}
		} else {
			probeInfo.ts_probe = 0
			probeInfo.probe_wait = 0
		}
		
		let useCwnd = min(min(snd_wnd, rmt_wnd), cwndInfo.cwnd)

		var lost = false
		var count = 0
		for (node, seg) in outboundOutBuffer.makeIterator() {
			defer {
				count &+= 1
			}
			if seg.data.runtimeMetadata.xmit == 0 {
				node.value!.data.runtimeMetadata.xmit = 1
				node.value!.data.runtimeMetadata.rto = UInt32(rttInfo.rx_rto)
				node.value!.data.runtimeMetadata.resendts = now &+ node.value!.data.runtimeMetadata.rto
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:node.value!.data)), promise:node.value!.writePromise)
			} else if itimeDiff(later:now, earlier:seg.data.runtimeMetadata.resendts) >= 0 {
				node.value!.data.runtimeMetadata.xmit &+= 1
				node.value!.data.runtimeMetadata.rto = node.value!.data.runtimeMetadata.rto &+ (node.value!.data.runtimeMetadata.rto / 2)
				node.value!.data.runtimeMetadata.resendts = now &+ node.value!.data.runtimeMetadata.rto
				lost = true
				context.write(handler.wrapOutboundOut(PeerAssociated(publicKey:peerPublicKey, associatedValue:node.value!.data)), promise:node.value!.writePromise)
				// Dead link occured. Wipe send queue
				if node.value!.data.runtimeMetadata.xmit >= 20 {
					for (node, _) in outboundOutBuffer.makeIterator() {
						node.value!.ackPromise?.fail(DeadlinkError())
					}
					outboundOutBuffer.clear()
					break
				}
			}
			guard count < snd_wnd else {
				break
			}
		}
		
		if lost == true {
			cwndInfo.ssthresh = useCwnd / 2
			if cwndInfo.ssthresh < IKCP_THRESH_MIN { cwndInfo.ssthresh = IKCP_THRESH_MIN }
			self.cwndInfo.cwnd = 1
			cwndInfo.incr = mss
		}
		if cwndInfo.cwnd < 1 {
			self.cwndInfo.cwnd = 1
			cwndInfo.incr = mss
		}
	}
}
