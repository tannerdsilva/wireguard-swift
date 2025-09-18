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

public func iclock() -> UInt32 {
	let now = DispatchTime.now().uptimeNanoseconds
	return UInt32(now / 1_000_000)  // nanoseconds → milliseconds
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

internal struct KCPControlBlock {
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

	var snd_queue = LinkedList<(data:KCPSegment, writePromise:EventLoopPromise<Void>?, ackPromise:EventLoopPromise<Void>?)>()		// user data waiting to be segmented and sent out
	// public var rcv_queue = LinkedList<KCPSegment>()		// Fully reassembled segments ready to return to application
	// public var snd_buf = LinkedList<KCPSegment>()			// Segments sent and waiting to be ACKed
	// public var rcv_buf = LinkedList<KCPSegment>()			// Segments received out of oder and waiting to be reassembled
	
	/// acklist is nil when ackcount == 0. variable is safe to access any time ackcount > 0
	private var acklist:UnsafeMutableBufferPointer<UInt32>!
	var ackcount:UInt32
	var ackblock:UInt32

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
		
		// self.inactiveA = true
		// self.inactiveB = true
	}

	// KCP Send
	// - Segments a ByteBuffer and puts the fragmented ByteBuffer into snd_queue with the appropriate write/ack promise at the last fragment.
	@available(*, noasync)
	public mutating func send(_ inputBuffer:ByteBuffer, count len:Int, writePromise: EventLoopPromise<Void>? = nil, ackPromise: EventLoopPromise<Void>?) throws(SendError) -> Int {
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
				snd_queue.addTail((seg, writePromise, ackPromise))
			} else {
				snd_queue.addTail((seg, nil, nil))
			}
			
			sent += fragSize
			i += 1
		}
		return sent
	}

	@available(*, noasync)
	internal mutating func updateAck(rtt: Int32) {
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
	internal mutating func shrinkBuff() {
		if let node = snd_queue.front {
			snd_una = node.value!.sn
		} else {
			snd_una = snd_nxt
		}
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

	// KCP Flush
	// - Sends any pending ACKs
	// - Sends any pending Probes
	// - Sends any pending data packets that can be sent
	@available(*, noasync)
	public mutating func flush(current:UInt32, byteBuffer:inout ByteBuffer) -> Bool {
		self.current = current
		
		let wnd = wndUnused()
		// Create  a basic segment for acks
		var header = KCPSegment.Header(conv: conv, cmd: KCPSegment.Command(rawValue: IKCP_CMD_ACK)!, frg: 0, sn: 0, len: 0)
		var seg = KCPSegment(header: header, data: ByteBufferView())
		seg.header.receiveWindowSize = wnd
		seg.header.una = rcv_nxt
		seg.header.timestamp = 0

		// Send pending acks
		for i in 0..<ackcount {
			
			ackGet(p:Int(i), sn:&seg.header.sequenceNumber, ts:&seg.header.timestamp)
			byteBuffer.clear()
			seg.encode(to: &byteBuffer)
			// OUTPUT HERE -------------------------
		}
		ackcount = 0
		
			newSeg.wnd = wnd
			newSeg.ts = current
			newSeg.una = rcv_nxt
			newSeg.resendts = current
			newSeg.rto = UInt32(rx_rto)
			newSeg.fastack = 0
			newSeg.xmit = 0
		
		if snd_queue.count == 0 {
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
			seg.cmd = IKCP_CMD_WASK
			if ptrOffset + Int(IKCP_OVERHEAD) > Int(mtu) {
				output(UnsafeMutableBufferPointer(start:buffer, count:ptrOffset), nil)
				ptrOffset = 0
			}
			ptrOffset = ikcp_segment.encode(seg, to:buffer + ptrOffset)
		}
		// If send_probe has been received, send tell_probe
		if (probe & IKCP_ASK_TELL) != 0 {
			seg.cmd = IKCP_CMD_WINS
			if ptrOffset + Int(IKCP_OVERHEAD) > Int(mtu) {
				output(UnsafeMutableBufferPointer(start:buffer, count:ptrOffset), nil)
			}
			ptrOffset = ikcp_segment.encode(seg, to:buffer + ptrOffset)
		}
		probe = 0
		
		var cwnd = min(snd_wnd, rmt_wnd)
		if nocwnd == 0 {
			cwnd = min(cwnd, self.cwnd)
		}
		
		let rtomin:UInt32 = nodelay == 0 ? UInt32(rx_rto) >> 3 : 0
		
		var change = false
		var lost = false
		
		for (node, seg) in snd_buf.makeIterator() {
			var needsend = false
			if seg.xmit == 0 {
				needsend = true
				seg.xmit = 1
				seg.rto = UInt32(rx_rto)
				seg.resendts = current &+ seg.rto &+ rtomin
			} else if itimeDiff(later:current, earlier:seg.resendts) >= 0 {
				needsend = true
				seg.xmit &+= 1
				xmit &+= 1
				if nodelay == 0 {
					seg.rto = seg.rto &+ max(UInt32(seg.rto), UInt32(rx_rto))
				} else {
					let step:UInt32 = (nodelay < 2) ? seg.rto : UInt32(rx_rto)
					seg.rto = seg.rto &+ step / 2
				}
				seg.resendts = current &+ seg.rto
                lost = true
			} else if seg.fastack >= resent {
				// fast‑retransmit (duplicate ACKs)
				if Int32(seg.xmit) <= fastlimit || fastlimit <= 0 {
					needsend = true
					seg.xmit &+= 1
					seg.fastack = 0
					seg.resendts = current &+ seg.rto
					change = true
				}
			}
			
			if needsend {
				inactiveA = false
				inactiveB = false
				seg.ts = current
				seg.una = rcv_nxt
				let need = Int(IKCP_OVERHEAD) + Int(seg.len)
				

				if ptrOffset + need > Int(mtu) {
					output(UnsafeMutableBufferPointer(start:buffer, count:ptrOffset), node.prev.value?.associatedInstances)
					ptrOffset = 0
				}
				ptrOffset += ikcp_segment.encode(seg, to:buffer + ptrOffset)
				
				if seg.xmit >= dead_link {
					state = UInt32(bitPattern:Int32(-1))
					snd_buf.clear()
				}
			}
		}
		
		if ptrOffset > 0 {
			output(UnsafeMutableBufferPointer(start:buffer, count:ptrOffset), snd_buf.back?.value?.associatedInstances)
		}
		
		if change == true {
			let inflight = snd_nxt &- snd_una
			ssthresh = inflight / 2
			if ssthresh < IKCP_THRESH_MIN { ssthresh = IKCP_THRESH_MIN }
			self.cwnd = ssthresh &+ resent
			incr = self.cwnd &* mss
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
		if(inactiveA && inactiveB) {
			return true
		} else {
			return false
		}
	}

}