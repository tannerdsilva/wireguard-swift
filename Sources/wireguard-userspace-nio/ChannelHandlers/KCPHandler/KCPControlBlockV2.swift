import NIO

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

public enum FatalBlockError:Swift.Error {
	case deadLink
}

public func iclock(_ delay:UInt64) -> UInt32 {
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
let IKCP_WND_SND:UInt32 = 2048
let IKCP_WND_RCV:UInt32 = 2048
let IKCP_OVERHEAD:UInt32 = 24
let IKCP_DEADLINK:UInt32 = 20
let IKCP_THRESH_INIT:UInt32 = 2
let IKCP_THRESH_MIN:UInt32 = 2
let IKCP_PROBE_INIT:UInt32 = 7000
let IKCP_PROBE_LIMIT:UInt32 = 120000

internal final class KCPControlBlock {
	/// conversation id
	var conv:UInt32
	/// maximum transmission unit: the largest udp packet accepted
	var mtu:UInt32
	/// maximum segment size: largest amount of data per segment
	var mss:UInt32
	
	/// earliest unacknowledged segment
	var snd_una:UInt32
	/// next segment number to send
	var snd_nxt:UInt32
	/// next expected segment number from peer
	var rcv_nxt:UInt32

	/// timestamp of the most recent packet received (used for RTT calculation)
	var ts_recent:UInt32
	var ts_lastack:UInt32	// Timestamp of the last ACK sent
	var ssthresh:UInt32	// Slow start theshold

	var rx_rttval:UInt32	// Smoothed RTT Variance
	var rx_srtt:UInt32	// Smoothed RTT
	var rx_rto:UInt32

	// Retransmission timeout (dynamically calculated)
	var rx_minrto:UInt32	// Minimum RTO allowed
	var rx_maxrto:UInt32

	var snd_wnd:UInt32		// Sender's Window: How many unacked segments willing to send
	var rcv_wnd:UInt32		// Receivers Window: How many segments we can accept
	var rmt_wnd:UInt32		// Remote's advertised receive window

	var cwnd:UInt32		// Congestion Window
	var incr:UInt32
	var probe:UInt32		// Flags for window probing

	var nodelay:UInt32		// 1 for nodelay mode

	var ts_probe:UInt32	    // Next scheduled probe time
	var probe_wait:UInt32	// Time to wait before probing again
	
	var snd_buf = LinkedList<(data:KCPSegment, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?)>()		// user data waiting to be segmented and sent out
	public var receiveQueue = LinkedList<KCPSegment>()		// Fully reassembled segments ready to return to application
	public var receiveBuffer = LinkedList<KCPSegment>()			// Segments received out of oder and waiting to be reassembled
	
	/// acklist is nil when ackcount == 0. variable is safe to access any time ackcount > 0
	private var acklist = LinkedList<(sn:UInt32, ts:UInt32)>()

	var nocwnd:Bool
		
	var delay:UInt64 = 0

	init(conv: UInt32, mtu:UInt32 = 1400) {
		self.conv = conv
		self.mtu = mtu
		self.mss = mtu - IKCP_OVERHEAD

		self.snd_una = 0
		self.snd_nxt = 0
		self.rcv_nxt = 0

		self.ts_recent = 0
		self.ts_lastack = 0
		self.ssthresh = IKCP_THRESH_INIT

		self.rx_rttval = 0
		self.rx_srtt = 0
		self.rx_rto = IKCP_RTO_DEF
		self.rx_minrto = IKCP_RTO_MIN
		self.rx_maxrto = IKCP_RTO_MAX

		self.snd_wnd = IKCP_WND_SND
		self.rcv_wnd = IKCP_WND_RCV
		self.rmt_wnd = IKCP_WND_RCV
		self.cwnd = 0
		self.probe = 0

		self.nodelay = 0

		self.ts_probe = 0
		self.probe_wait = 0

		self.incr = 0

		self.nocwnd = false
	}

	// Receive data from the queue of in order messages
	private func produceInboundOut(context:ChannelHandlerContext) -> [ByteBuffer] {
		var completeMessages:[ByteBuffer] = []

		while true {
			guard receiveQueue.front != nil else {
				break
			}

			let expectedFragments = receiveQueue.front!.value!.header.fragmentID

			guard receiveQueue.count >= expectedFragments + 1 else {
				break
			}

			var singleMessage = context.channel.allocator.buffer(capacity: (Int(expectedFragments) + 1) * Int(mtu))
			
			for (_, seg) in receiveQueue {
				singleMessage.writeBytes(seg.data)
				_ = receiveQueue.popFront()

				if(seg.header.fragmentID == 0) {
					break
				}
			}

			completeMessages.append(singleMessage)
		}

		return completeMessages
	}

	private func parseUna(una: UInt32) {
		segLoop: for (curNode, seg) in snd_buf.makeIterator() {
			if Int32(bitPattern: una &- seg.data.header.sequenceNumber) > 0 {
				curNode.value!.ackPromise?.succeed()
				snd_buf.remove(curNode)
			} else {
				break segLoop
			}
		}
	}

	private func updateRtt(rtt: UInt32) {
		if rx_srtt == 0 {
			rx_srtt = rtt
			rx_rttval = rtt / 2
		} else {
			var delta = Int32(rtt) - Int32(rx_srtt)
			if delta < 0 {
				delta = -delta
			}
			rx_rttval = ((3 * rx_rttval + UInt32(delta)) / 4)
			rx_srtt = (7 * rx_srtt + rtt) / 8
			if rx_srtt < 1 {
				rx_srtt = 1
			}
		}
		
		// calculate the retransmission time
		let rtoUnbound:UInt32 = rx_srtt + 4 * rx_rttval
		rx_rto = ibound(rx_minrto, rtoUnbound, rx_maxrto)
	}

	// Acknowledges a specific segment sn and removes if from the `snd_buff`
	// Called when we receive an ack
	private func parseAck(sn:UInt32) {
		guard Int32(bitPattern:sn &- snd_una) >= 0 && Int32(bitPattern:sn &- snd_nxt) < 0 else {
			return
		}
		segLoop: for (curNode, seg) in snd_buf.makeIterator() {
			guard seg.data.header.sequenceNumber != sn else {
				curNode.value!.ackPromise?.succeed()
				snd_buf.remove(curNode)
				break segLoop
			}
			guard Int32(bitPattern:sn &- seg.data.header.sequenceNumber) >= 0 else {
				break segLoop
			}
		}
	}

	private func ackPush(sn: UInt32, ts: UInt32) {
		acklist.addTail((sn, ts))
	}

	// Input a kcp segment and parse it
	public func input(_ seg:KCPSegment, context:ChannelHandlerContext) throws -> [ByteBuffer] {
		func syncSendBuff() {
			if let node = snd_buf.front {
				snd_una = node.value!.data.header.sequenceNumber
			} else {
				snd_una = snd_nxt
			}
		}

		let prevUna = snd_una
		var returnedMessages:[ByteBuffer] = []

		guard conv == seg.header.conversationID else {
			throw InputError.convValueMismatch
		}

		guard seg.data.count == seg.header.dataLength else {
			throw InputError.partialTrailingData
		}

		// Functions applied for every segment
		parseUna(una: seg.header.una)
		syncSendBuff()

		let sn = seg.header.sequenceNumber
		let ts = seg.header.timestamp

		switch seg.header.command {
			case KCPSegment.Command.ack:
				if(itimeDiff(later: iclock(delay), earlier: ts) >= 0) {
					updateRtt(rtt: iclock(delay) &- ts)
				}
				parseAck(sn: sn)
				syncSendBuff()
			case KCPSegment.Command.push:
				if Int32(bitPattern:sn &- (rcv_nxt + rcv_wnd)) < 0 {
					ackPush(sn:sn, ts:ts)
					if Int32(bitPattern:sn &- rcv_nxt) >= 0 {
						parseData(seg)
						returnedMessages = produceInboundOut(context: context)
					}
				}
			case KCPSegment.Command.probeRequest:
				probe |= IKCP_ASK_TELL
				// if (rcv_queue.count == 0) {
				// 	inactiveA = true
				// }
			case KCPSegment.Command.probeResponse:
				// if(rcv_queue.count == 0) {
				// 	inactiveB = true
				// }
				// nothing to do here
				break;
		}

		if itimeDiff(later:snd_una, earlier:prevUna) > 0 {
			if cwnd < rmt_wnd {
				let mss = self.mss
				if cwnd < ssthresh {
					cwnd &+= 1
					incr &+= mss
				} else {
					if incr < mss {
						incr = mss
					}
					incr &+= (mss * mss) / incr + (mss / 16)
					if ((cwnd &+ 1) &* mss <= incr) {
						cwnd = (incr &+ mss &- 1) / (mss > 0 ? mss : 1)
					}
				}
				
				if cwnd > rmt_wnd {
					cwnd = rmt_wnd
					incr = rmt_wnd &* mss
				}
			}
		}

		return returnedMessages
	}

	// KCP ParseData
	// - Called by input
	// - Parses an individual PUSH segment
	// - If it's a new segment, puts the segment into the rcv_buf in the correct order
	// - Moves any segments it can (sequentially) into the receive queue
	@available(*, noasync)
	private func parseData(_ newseg: KCPSegment) {
		let sn = newseg.header.sequenceNumber
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
		if isDuplicate == false {
			if let anchor = insertAfterNode {
				receiveBuffer.insert(newseg, after:anchor)
			} else {
				receiveBuffer.add(newseg)
			}
		}
		while let firstNode = receiveBuffer.front, firstNode.value!.header.sequenceNumber == rcv_nxt && receiveQueue.count < rcv_wnd {
			receiveBuffer.remove(firstNode)
			receiveQueue.addTail(firstNode)
			rcv_nxt &+= 1
		}
	}

	public func send(_ inputBuffer: ByteBuffer, writePromise: EventLoopPromise<Void>? = nil, ackPromise: EventLoopPromise<Void>? = nil) -> Bool {
		let count = (inputBuffer.readableBytes + Int(mss) - 1) / Int(mss)
		var bufferIsFull = false
		if(UInt32(count) + snd_buf.count < snd_wnd ) {
			bufferIsFull = true
		}

		var i = 0
		for offset in stride(from: 0, to: inputBuffer.readableBytes, by: Int(mss)) {
			let fragSize = min(Int(mss), inputBuffer.readableBytes - offset)
			
			let view = inputBuffer.getSlice(at: inputBuffer.readerIndex + offset, length: fragSize)

			let header = KCPSegment.Header(conv: conv, cmd: KCPSegment.Command(rawValue: IKCP_CMD_PUSH)!, frg: UInt8(count - i - 1), sn: snd_nxt, len: UInt32(fragSize))
			snd_nxt &+= 1
			let seg = KCPSegment(header: header, data: view!.readableBytesView)
			
			if (i == count-1) {
				snd_buf.addTail((seg, writePromise, ackPromise))
			} else {
				snd_buf.addTail((seg, nil, nil))
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
	public func getOutboundSegments(byteBuffer:inout ByteBuffer) -> [(KCPSegment, EventLoopPromise<Void>?)]{	
		var outboundOutSegments:[(KCPSegment, EventLoopPromise<Void>?)] = []	

		let header = KCPSegment.Header(conv:conv, cmd:.ack, frg:0, sn:0, len:0)

		var seg = KCPSegment(header: header, data: ByteBufferView())
		seg.header.receiveWindowSize = wndUnused()
		seg.header.una = rcv_nxt
		seg.header.timestamp = 0

		// Send pending acks
		for (_, ack) in acklist {
			seg.header.sequenceNumber = ack.sn
			seg.header.timestamp = ack.ts
			
			outboundOutSegments.append((seg, nil))
		}
		if (!acklist.isEmpty) {
			acklist.clear()
		}
				
		// Only manage probes if we have nothing to send
		if rmt_wnd == 0 || snd_buf.count == 0 {
			// Update probe time variables and prepare send ask_probe if needed
			if probe_wait == 0 {
				probe_wait = IKCP_PROBE_INIT
			} else if itimeDiff(later:iclock(delay), earlier:ts_probe) >= 0 {
				if probe_wait < IKCP_PROBE_INIT {
					probe_wait = IKCP_PROBE_INIT
				}
				probe_wait += probe_wait / 2
				if probe_wait > IKCP_PROBE_LIMIT {
					probe_wait = IKCP_PROBE_LIMIT
				}
				ts_probe = iclock(delay) + probe_wait
				probe |= IKCP_ASK_SEND
			}
		} else {
			ts_probe = 0
			probe_wait = 0
		}
		
		// If snd_buf = 0 and probe time has passed. Send send_probe
		if (probe & IKCP_ASK_SEND) != 0 {
			seg.header.command = KCPSegment.Command(rawValue: IKCP_CMD_WASK)!
			
			outboundOutSegments.append((seg, nil))
		}
		// If send_probe has been received, send tell_probe
		if (probe & IKCP_ASK_TELL) != 0 {
			seg.header.command = KCPSegment.Command(rawValue: IKCP_CMD_WINS)!
			
			outboundOutSegments.append((seg, nil))
		}
		probe = 0
				
		var cwnd = min(snd_wnd, rmt_wnd)
		if nocwnd == false {
			cwnd = min(cwnd, self.cwnd)
		}

		let rtomin:UInt32 = nodelay == 0 ? UInt32(rx_rto) >> 3 : 0
		
		var lost = false
		
		var count = 0
		for (node, seg) in snd_buf.makeIterator() {
			var needsend = false
			if seg.data.runtimeMetadata.xmit == 0 {
				needsend = true
				node.value!.data.runtimeMetadata.xmit = 1
				node.value!.data.runtimeMetadata.rto = UInt32(rx_rto)
				node.value!.data.runtimeMetadata.resendts = iclock(delay) &+ node.value!.data.runtimeMetadata.rto &+ rtomin
			} else if itimeDiff(later:iclock(delay), earlier:seg.data.runtimeMetadata.resendts) >= 0 {
				needsend = true
				node.value!.data.runtimeMetadata.xmit &+= 1
				if nodelay == 0 {
					node.value!.data.runtimeMetadata.rto = seg.data.runtimeMetadata.rto &+ max(UInt32(seg.data.runtimeMetadata.rto), UInt32(rx_rto))
				} else {
					let step:UInt32 = (nodelay < 2) ? node.value!.data.runtimeMetadata.rto : UInt32(rx_rto)
					node.value!.data.runtimeMetadata.rto = node.value!.data.runtimeMetadata.rto &+ step / 2
				}
				node.value!.data.runtimeMetadata.resendts = iclock(delay) &+ node.value!.data.runtimeMetadata.rto
				lost = true
			} 
			
			if needsend {
				// Update timestamp and una
				node.value!.data.header.timestamp = iclock(delay)
				node.value!.data.header.una = rcv_nxt	
				node.value!.data.header.receiveWindowSize = wndUnused()			

				outboundOutSegments.append((node.value!.data, node.value!.writePromise))
				
				// Dead link occured. Wipe send queue
				if node.value!.data.runtimeMetadata.xmit >= 20 {
					for (node, _) in snd_buf.makeIterator() {
						node.value!.ackPromise?.fail(FatalBlockError.deadLink)
					}
					snd_buf.clear()
					// Set inactive to true so it can be cleared later
					break
				}
			}
			count += 1
			if(count == snd_wnd) {
				break
			}
		}
		
		if lost == true {
			ssthresh = cwnd / 2
			if ssthresh < IKCP_THRESH_MIN { ssthresh = IKCP_THRESH_MIN }
			self.cwnd = 1
			incr = mss
		}
		if cwnd < 1 {
			self.cwnd = 1
			incr = mss
		}

		return outboundOutSegments
	}

	public func setNoDelay(_ nodelay:Int, nc:Int) {
		// nodelay flag
		if nodelay >= 0 {
			self.nodelay = UInt32(nodelay)
			self.rx_minrto = (nodelay != 0) ? UInt32(IKCP_RTO_NDL) : UInt32(IKCP_RTO_MIN)
		}

		// no congestion‑window
		if nc > 0 {
			self.nocwnd = true
		} else {
			self.nocwnd = false
		}
	}
}
