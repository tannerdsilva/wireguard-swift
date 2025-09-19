import NIO
import Dispatch

public enum SendError:Swift.Error {
	case mssValueError
	case inputLengthError
	case invalidDataCountForReceiveWindow
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

public func iclock() -> UInt32 {
	let now = DispatchTime.now().uptimeNanoseconds
	return UInt32(now / 1_000_000) // nanoseconds → milliseconds
}
@inline(__always) private func imax(_ a: UInt32, _ b: UInt32) -> UInt32 {
	return a > b ? a : b
}
@inline(__always) private func ibound(_ lower: Int32, _ value: Int32, _ upper: Int32) -> Int32 {
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
let IKCP_WND_SND:UInt32 = 4096
let IKCP_WND_RCV:UInt32 = 4096
let IKCP_MTU_DEF:UInt32 = 1400
let IKCP_ACK_FAST:UInt32 = 3
let IKCP_INTERVAL:UInt32 = 100
let IKCP_OVERHEAD:UInt32 = 24
let IKCP_DEADLINK:UInt32 = 20
let IKCP_THRESH_INIT:UInt32 = 2
let IKCP_THRESH_MIN:UInt32 = 2
let IKCP_PROBE_INIT:UInt32 = 7000
let IKCP_PROBE_LIMIT:UInt32 = 120000
let IKCP_FASTACK_LIMIT:UInt32 = 5

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

	var rx_rttval:Int32	// Smoothed RTT Variance
	var rx_srtt:Int32	// Smoothed RTT
	var rx_rto:Int32

	// Retransmission timeout (dynamically calculated)
	var rx_minrto:Int32	// Minimum RTO allowed
	var rx_maxrto:Int32

	var snd_wnd:UInt32		// Sender's Window: How many unacked segments willing to send
	var rcv_wnd:UInt32		// Receivers Window: How many segments we can accept
	var rmt_wnd:UInt32		// Remote's advertised receive window
	var cwnd:UInt32		// Congestion Window
	var probe:UInt32		// Flags for window probing

	var current:UInt32
	var interval:UInt32
	var ts_flush:UInt32
	var xmit:UInt32		// Total number of transmissions

	var nodelay:UInt32		// 1 for nodelay mode

	var ts_probe:UInt32	// Next scheduled probe time
	var probe_wait:UInt32	// Time to wait before probing again

	var dead_link:UInt32	// Max number of retransmits before considering the link dead
	var incr:UInt32

	var snd_buf = LinkedList<(data:KCPSegment, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?)>()		// user data waiting to be segmented and sent out
	public var rcv_queue = LinkedList<KCPSegment>()		// Fully reassembled segments ready to return to application
	public var rcv_buf = LinkedList<KCPSegment>()			// Segments received out of oder and waiting to be reassembled
	
	/// acklist is nil when ackcount == 0. variable is safe to access any time ackcount > 0
	private var acklist:UnsafeMutableBufferPointer<UInt32>!
	var ackcount:UInt32
	var ackblock:UInt32

	var inactiveA:Bool
	var inactiveB:Bool

	init(conv: UInt32) {
		self.conv = conv
		self.mtu = IKCP_MTU_DEF
		self.mss = mtu - IKCP_OVERHEAD

		self.snd_una = 0
		self.snd_nxt = 0
		self.rcv_nxt = 0

		self.ts_recent = 0
		self.ts_lastack = 0
		self.ssthresh = IKCP_THRESH_INIT

		self.rx_rttval = 0
		self.rx_srtt = 0
		self.rx_rto = Int32(IKCP_RTO_DEF)
		self.rx_minrto = Int32(IKCP_RTO_MIN)
		self.rx_maxrto = Int32(IKCP_RTO_MAX)

		self.snd_wnd = IKCP_WND_SND
		self.rcv_wnd = IKCP_WND_RCV
		self.rmt_wnd = IKCP_WND_RCV
		self.cwnd = 0
		self.probe = 0

		self.current = 0
		self.interval = IKCP_INTERVAL
		self.ts_flush = IKCP_INTERVAL
		self.xmit = 0

		self.nodelay = 0

		self.ts_probe = 0
		self.probe_wait = 0

		self.dead_link = IKCP_DEADLINK
		self.incr = 0

		self.acklist = nil
		self.ackcount = 0
		self.ackblock = 0

		// self.fastresend = 0
		// self.fastlimit = Int64(IKCP_FASTACK_LIMIT)
		// self.nocwnd = 1
		
		self.inactiveA = true
		self.inactiveB = true
	}

	// KCP Send
	// - Segments a ByteBuffer and puts the fragmented ByteBuffer into snd_buf with the appropriate write/ack promise at the last fragment.
	@available(*, noasync)
	public func send(_ inputBuffer:ByteBuffer, writePromise: EventLoopPromise<Void>? = nil, ackPromise: EventLoopPromise<Void>?) throws(SendError) -> Int {
		let len = inputBuffer.readableBytes
		guard mss > 0 else {
			writePromise?.fail(SendError.mssValueError)
			ackPromise?.fail(SendError.mssValueError)
			throw SendError.mssValueError
		}
		guard len >= 0 else {
			writePromise?.fail(SendError.inputLengthError)
			ackPromise?.fail(SendError.inputLengthError)
			throw SendError.inputLengthError
		}
		var sent = 0

		
		var count:Int
		if len <= Int(mss) {
			count = 1
		} else {
			count = (len + Int(mss) - 1) / Int(mss)
		}
		
		if count == 0 {
			count = 1
		}
		
		var i = 0
		for offset in stride(from: 0, to: len, by: Int(mss)) {
			let fragSize = min(Int(mss), len - offset)
			
			let view = inputBuffer.getSlice(at: inputBuffer.readerIndex + offset, length: fragSize)

			var header = KCPSegment.Header(conv: conv, cmd: KCPSegment.Command(rawValue: IKCP_CMD_PUSH)!, frg: UInt8(count - i - 1), sn: snd_nxt, len: UInt32(fragSize))
			snd_nxt &+= 1
			var seg = KCPSegment(header: header, data: view!.readableBytesView)
			
			
			if(i == count-1) {
				snd_buf.addTail((seg, writePromise, ackPromise))
			} else {
				snd_buf.addTail((seg, nil, nil))
			}
			
			sent += fragSize
			i += 1
		}
		return sent
	}

	@available(*, noasync)
	internal func updateAck(rtt: Int32) {
		if rx_srtt == 0 {
			rx_srtt = rtt
			rx_rttval = rtt / 2
		} else {
			var delta = rtt - rx_srtt
			if delta < 0 {
				delta = -delta
			}
			rx_rttval = ((3 * rx_rttval + delta) / 4)
			rx_srtt = (7 * rx_srtt + rtt) / 8
			if rx_srtt < 1 {
				rx_srtt = 1
			}
		}
		
		// calculate the retransmission time
		let rtoUnbound:Int32 = Int32(rx_srtt) + Int32(imax(UInt32(interval), UInt32(4 * rx_rttval)))
		rx_rto = ibound(rx_minrto, rtoUnbound, Int32(rx_maxrto))
	}
	
	/// Syncs `send_una` up to sync with the current contents of the `snd_buf`
	internal func shrinkBuff() {
		if let node = snd_buf.front {
			snd_una = node.value!.data.header.sequenceNumber
		} else {
			snd_una = snd_nxt
		}
	}

	/// Acknowledges a specific segment sn and removes if from the `snd_buff`
	internal func parseAck(sn:UInt32) {
		guard itimeDiff(later:sn, earlier:snd_una) >= 0 && itimeDiff(later:sn, earlier:snd_nxt) < 0 else {
			return
		}
		segLoop: for (curNode, seg) in snd_buf.makeIterator() {
			guard seg.data.header.sequenceNumber != sn else {
				curNode.value!.ackPromise?.succeed()
				snd_buf.remove(curNode)
				break segLoop
			}
			guard itimeDiff(later:sn, earlier:seg.data.header.sequenceNumber) >= 0 else {
				break segLoop
			}
		}
	}
	
	@available(*, noasync)
	internal func parseUna(una: UInt32) {
		segLoop: for (curNode, seg) in snd_buf.makeIterator() {
			if itimeDiff(later:una, earlier:seg.data.header.sequenceNumber) > 0 {
				curNode.value!.ackPromise?.succeed()
				snd_buf.remove(curNode)
			} else {
				break segLoop
			}
		}
	}
	
	@available(*, noasync)
	internal func parseFastAck(sn: UInt32, ts: UInt32) {
		guard itimeDiff(later:sn, earlier:snd_una) >= 0 && itimeDiff(later:sn, earlier:snd_nxt) < 0 else {
			return
		}
		segLoop: for (node, seg) in snd_buf.makeIterator() {
			guard itimeDiff(later:sn, earlier:seg.data.header.sequenceNumber) < 0 else {
				break segLoop
			}
			if sn != seg.data.header.sequenceNumber {
				#if FASTACK_CONSERVE
				if itimeDiff(ts, seg.ts) >= 0 {
					seg.fastack &+= 1
				}
				#else
				node.value!.data.header.fastack &+= 1
				#endif
			}
		}
	}
	
	@available(*, noasync)
	internal func ackPush(sn: UInt32, ts: UInt32) {
		let newSize = ackcount + 1
		if newSize > ackblock {
			var newBlock:UInt32 = 8
			while newBlock < newSize {
				newBlock <<= 1
			}
			let newAcklistSize = Int(newBlock * 2)
			let newList = UnsafeMutableBufferPointer<UInt32>.allocate(capacity:newAcklistSize)
			for i in 0..<ackcount {
				newList[Int(i * 2)] = acklist[Int(i * 2)]
				newList[Int(i * 2) + 1] = acklist[Int(i * 2) + 1]
			}
			for i in Int(ackcount * 2)..<newAcklistSize {
				newList[i] = 0
			}
			ackblock = newBlock
			acklist = newList
		}
		let idx = Int(ackcount * 2)
		acklist[idx] = sn
		acklist[idx + 1] = ts
		ackcount &+= 1
	}

	@available(*, noasync)
	internal func ackGet(p:Int, sn: inout UInt32, ts: inout UInt32) {
		guard p >= 0 && UInt32(p) < ackcount else {
			fatalError("invalid p index passed to ackGet")
		}
		let base = p * 2
		sn = acklist[base]
		ts = acklist[base + 1]
	}

	@available(*, noasync)
	internal func wndUnused() -> UInt16 {
		return UInt16(rcv_wnd)
	}

	// KCP Input
	// - Input segments read from network
	// - Filters segments by the segment command
	// - Update snd_wnd, parseUna, and shrinkbuff for ALL segments
	@available(*, noasync)
	public func input(_ inputBuffer:inout ByteBuffer) throws(InputError) {
		let count = inputBuffer.readableBytes
		let prevUna = snd_una
		var maxAck:UInt32 = 0
		var latestTS:UInt32 = 0
		var gotAck = false
		guard count >= IKCP_OVERHEAD else {
			throw InputError.invalidInputCount
		}
		
		var left = count
		while left >= IKCP_OVERHEAD {
			let seg = KCPSegment(decode: &inputBuffer)!
			
			guard seg.header.conversationID == self.conv else {
				throw InputError.convValueMismatch
			}
			
			left -= Int(IKCP_OVERHEAD)
			guard seg.data.count == seg.header.dataLength else {
				throw InputError.partialTrailingData
			}

			// Get the remote window size and change snd_wnd accordingly
			rmt_wnd = UInt32(seg.header.receiveWindowSize)
			snd_wnd = min(snd_wnd, rmt_wnd)

			parseUna(una:seg.header.una)
			shrinkBuff()
			let sn = seg.header.sequenceNumber
			let ts = seg.header.timestamp
			switch seg.header.command {
				case KCPSegment.Command.ack:
					if itimeDiff(later:current, earlier:ts) >= 0 {
						updateAck(rtt:itimeDiff(later:current, earlier:ts))
					}
					parseAck(sn:sn)
					shrinkBuff()
					if gotAck == false {
						gotAck = true
						maxAck = sn
						latestTS = ts
					} else if itimeDiff(later:sn, earlier:maxAck) > 0 {
						#if FASTACK_CONSERVE
						if itimeDiff(ts, latestTS) > 0 {
							maxAck = sn
							latestTS = ts
						}
						#else
						maxAck = sn
						latestTS = ts
						#endif
					}
				case KCPSegment.Command.push:
					inactiveA = false
					inactiveB = false
					if itimeDiff(later:sn, earlier:self.rcv_nxt + rcv_wnd) < 0 {
						ackPush(sn:sn, ts:ts)
						if itimeDiff(later:sn, earlier:self.rcv_nxt) >= 0 {
							parseData(seg)
						}
					}
				case KCPSegment.Command.probeRequest:
					probe |= IKCP_ASK_TELL
					if(rcv_queue.count == 0) {
						inactiveA = true
					}
				case KCPSegment.Command.probeResponse:
					if(rcv_queue.count == 0) {
						inactiveB = true
					}
					// nothing to do here
					break;
				default:
					throw InputError.invalidCMD
			}
		}
		if gotAck {
			parseFastAck(sn:maxAck, ts:latestTS)
		}
	}

	// KCP ParseData
	// - Called by input
	// - Parses an individual PUSH segment
	// - If it's a new segment, puts the segment into the rcv_buf in the correct order
	// - Moves any segments it can (sequentially) into the receive queue
	@available(*, noasync)
	internal func parseData(_ newseg: KCPSegment) {
		let sn = newseg.header.sequenceNumber
		var isDuplicate = false
		guard itimeDiff(later:sn, earlier:rcv_nxt &+ rcv_wnd) < 0, itimeDiff(later:sn, earlier:rcv_nxt) >= 0 else {
			return
		}
		
		var insertAfterNode:LinkedList<KCPSegment>.Node? = nil
		segLoop: for (curNode, seg) in rcv_buf.makeReverseIterator() {
			guard seg.header.sequenceNumber != sn else {
				isDuplicate = true
				break segLoop
			}
			guard itimeDiff(later:sn, earlier:seg.header.sequenceNumber) <= 0 else {
				insertAfterNode = curNode
				break segLoop
			}
		}
		if isDuplicate == false {
			if let anchor = insertAfterNode {
				rcv_buf.insert(newseg, after:anchor)
			} else {
				rcv_buf.add(newseg)
			}
		}
		while let firstNode = rcv_buf.front, firstNode.value!.header.sequenceNumber == rcv_nxt && rcv_queue.count < rcv_wnd {
			rcv_buf.remove(firstNode)
			rcv_queue.addTail(firstNode)
			rcv_nxt &+= 1
		}
	}

	// KCP Receive
	// - 
	
	// @available(*, noasync)
	// public func receive(_ ptr:UnsafeMutableRawPointer?, len:Int) throws(ReceiveError) -> Int {
	// 	guard rcv_queue.isEmpty == false else {
	// 		throw ReceiveError.receiveQueueEmpty
	// 	}
	// 	let isPeek:Bool = (len < 0)
	// 	let absLen = isPeek ? -len : len
		
	// 	let peekSize = try peekSize()
	// 	guard peekSize <= absLen else {
	// 		throw ReceiveError.lengthTooSmall
	// 	}
	// 	var recover:Bool = false
	// 	if rcv_queue.count >= rcv_wnd {
	// 		recover = true
	// 	}
	// 	var copied = 0
	// 	nodeLoop: for (node, seg) in rcv_queue.makeIterator() {
	// 		if let buf = ptr, seg.len > 0 {
	// 			buf.advanced(by:copied).assumingMemoryBound(to:UInt8.self).update(from:seg.data, count:Int(seg.len))
	// 		}
	// 		copied += Int(seg.len)
	// 		if isPeek == false {
	// 			rcv_queue.remove(node)
	// 		}
	// 		guard seg.frg != 0 else {
	// 			break nodeLoop
	// 		}
	// 	}
		
	// 	#if DEBUG
	// 	guard copied == peekSize else {
	// 		fatalError("copied is not the same as peeksize. this is unexpected")
	// 	}
	// 	#endif
		
	// 	for (node, seg) in rcv_buf.makeIterator() {
	// 		if seg.sn == rcv_nxt && rcv_buf.count < rcv_wnd {
	// 			rcv_buf.remove(node)
				
	// 			rcv_queue.addTail(node)
				
	// 			rcv_nxt += 1
	// 		} else {
	// 			break
	// 		}
	// 	}
		
	// 	if rcv_queue.count < rcv_wnd && recover == true {
	// 		probe |= IKCP_ASK_TELL
	// 	}
	// 	return copied
	// }

	// KCP Flush
	// - Sends any pending ACKs
	// - Sends any pending Probes
	// - Sends any pending data packets that can be sent
	@available(*, noasync)
	public func flush(current:UInt32, byteBuffer:inout ByteBuffer) -> Bool {
		self.current = current
		
		let wnd = wndUnused()
		// Create a basic segment for acks
		let header = KCPSegment.Header(conv: conv, cmd: KCPSegment.Command(rawValue: IKCP_CMD_ACK)!, frg: 0, sn: 0, len: 0)
		var seg = KCPSegment(header: header, data: ByteBufferView())
		seg.header.receiveWindowSize = wnd
		seg.header.una = rcv_nxt
		seg.header.timestamp = 0

		// Send pending acks
		for i in 0..<ackcount {
			
			ackGet(p:Int(i), sn:&seg.header.sequenceNumber, ts:&seg.header.timestamp)
			// Check if we need to output data
			if(byteBuffer.readableBytes + Int(IKCP_OVERHEAD) > mtu) {
				// OUTPUT HERE -------------------------
				byteBuffer.clear(minimumCapacity: Int(IKCP_OVERHEAD))
			}
			seg.encode(to: &byteBuffer)
		}
		ackcount = 0
				
		// Only manage probes if we have nothing to send
		if snd_buf.count == 0 {
			// Update probe time variables and prepare send ask_probe if needed
			if probe_wait == 0 {
				probe_wait = IKCP_PROBE_INIT
			} else if itimeDiff(later:current, earlier:ts_probe) >= 0 {
				if probe_wait < IKCP_PROBE_INIT {
					probe_wait = IKCP_PROBE_INIT
				}
				probe_wait += probe_wait / 2
				if probe_wait > IKCP_PROBE_LIMIT {
					probe_wait = IKCP_PROBE_LIMIT
				}
				ts_probe = current + probe_wait
				probe |= IKCP_ASK_SEND
			}
		} else {
			ts_probe = 0
			probe_wait = 0
		}
		
		// If snd_buf = 0 and probe time has passed. Send send_probe
		if (probe & IKCP_ASK_SEND) != 0 {
			seg.header.command = KCPSegment.Command(rawValue: IKCP_CMD_WASK)!
			byteBuffer.clear()
			if(byteBuffer.readableBytes + Int(IKCP_OVERHEAD) > mtu) {
				// OUTPUT HERE -------------------------
				byteBuffer.clear(minimumCapacity: Int(IKCP_OVERHEAD))
			}
			seg.encode(to: &byteBuffer)
		}
		// If send_probe has been received, send tell_probe
		if (probe & IKCP_ASK_TELL) != 0 {
			seg.header.command = KCPSegment.Command(rawValue: IKCP_CMD_WINS)!
			if(byteBuffer.readableBytes + Int(IKCP_OVERHEAD) > mtu) {
				// OUTPUT HERE -------------------------
				byteBuffer.clear(minimumCapacity: Int(IKCP_OVERHEAD))
			}
			seg.encode(to: &byteBuffer)
		}
		probe = 0
				
		let rtomin:UInt32 = nodelay == 0 ? UInt32(rx_rto) >> 3 : 0
		
		for (node, seg) in snd_buf.makeIterator() {
			var needsend = false
			if seg.data.header.xmit == 0 {
				needsend = true
				node.value!.data.header.xmit = 1
				node.value!.data.header.rto = UInt32(rx_rto)
				node.value!.data.header.resendts = current &+ node.value!.data.header.rto &+ rtomin
			} else if itimeDiff(later:current, earlier:seg.data.header.resendts) >= 0 {
				needsend = true
				node.value!.data.header.xmit &+= 1
				xmit &+= 1
				if nodelay == 0 {
					node.value!.data.header.rto = seg.data.header.rto &+ max(UInt32(seg.data.header.rto), UInt32(rx_rto))
				} else {
					let step:UInt32 = (nodelay < 2) ? node.value!.data.header.rto : UInt32(rx_rto)
					node.value!.data.header.rto = node.value!.data.header.rto &+ step / 2
				}
				node.value!.data.header.resendts = current &+ node.value!.data.header.rto
			} 
			
			if needsend {
				inactiveA = false
				inactiveB = false

				// Update timestamp and una
				node.value!.data.header.timestamp = current
				node.value!.data.header.una = rcv_nxt	
				node.value!.data.header.receiveWindowSize = wnd			

				if(byteBuffer.readableBytes + Int(IKCP_OVERHEAD) + Int(node.value!.data.header.dataLength) > mtu) {
					// OUTPUT HERE -------------------------
					byteBuffer.clear(minimumCapacity: Int(mtu))
				}
				node.value!.data.encode(to: &byteBuffer)

				
				// Dead link occured. Wipe send queue
				if node.value!.data.header.xmit >= dead_link {
					for (node, _) in snd_buf.makeIterator() {
						node.value!.ackPromise?.fail(FatalBlockError.deadLink)
					}
					snd_buf.clear()
					// Set inactive to true so it can be cleared later
					break
				}
			}
		}

		if(byteBuffer.readableBytes != 0) {
			// OUTPUT HERE -------------------------
			byteBuffer.clear(minimumCapacity: Int(IKCP_OVERHEAD))
		}

		if(inactiveA && inactiveB) {
			return true
		} else {
			return false
		}
	}

}