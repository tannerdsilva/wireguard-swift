import RAW

let IKCP_RTO_NDL:UInt32 = 30
let IKCP_RTO_MIN:UInt32 = 100
let IKCP_RTO_DEF:UInt32 = 200
let IKCP_RTO_MAX:UInt32 = 60000
let IKCP_CMD_PUSH:UInt32 = 81
let IKCP_CMD_ACK:UInt32 = 82
let IKCP_CMD_WASK:UInt32 = 83
let IKCP_CMD_WINS:UInt32 = 84
let IKCP_ASK_SEND:UInt32 = 1
let IKCP_ASK_TELL:UInt32 = 2
let IKCP_WND_SND:UInt32 = 32
let IKCP_WND_RCV:UInt32 = 128
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

internal struct ikcp_segment {
	// internal var node:iqueue_head
	internal var conv:UInt32
	internal var cmd:UInt32
	internal var frg:UInt32
	internal var wnd:UInt32
	internal var ts:UInt32
	internal var sn:UInt32
	internal var una:UInt32
	internal var len:UInt32
	internal var resendts:UInt32
	internal var rto:UInt32
	internal var fastack:UInt32
	internal var xmit:UInt32
	internal var data:[UInt8]
}

internal struct ikcp_cb:~Copyable {
	internal var conv:UInt32
	internal var mtu:UInt32
	internal var mss:UInt32
	internal var state:UInt32

	internal var snd_una:UInt32
	internal var snd_nxt:UInt32
	internal var rcv_nxt:UInt32

	internal var ts_recent:UInt32
	internal var ts_lastack:UInt32
	internal var ssthresh:UInt32

	internal var rx_rttval:Int32
	internal var rx_srtt:Int32
	internal var rx_rto:Int32
	internal var rx_minrto:Int32

	internal var snd_wnd:UInt32
	internal var rcv_wnd:UInt32
	internal var rmt_wnd:UInt32
	internal var cwnd:UInt32
	internal var probe:UInt32

	internal var current:UInt32
	internal var interval:UInt32
	internal var ts_flush:UInt32
	internal var xmit:UInt32

	internal var nrcv_buf:UInt32
	internal var nsnd_buf:UInt32

	internal var nrcv_que:UInt32
	internal var nsnd_que:UInt32

	internal var nodelay:UInt32
	internal var updated:UInt32

	internal var ts_probe:UInt32
	internal var probe_wait:UInt32

	internal var dead_link:UInt32
	internal var incr:UInt32

	internal var snd_queue:[ikcp_segment]
	internal var rcv_queue:[ikcp_segment]
	internal var snd_buf:[ikcp_segment]
	internal var rcv_buf:[ikcp_segment]

	internal var acklist:UnsafeMutablePointer<UInt32>?
	internal var ackcount:UInt32
	internal var ackblock:UInt32

	internal var user:UnsafeMutableRawPointer
	internal var buffer:UnsafeMutablePointer<UInt8>

	internal var fastresend:Int64
	
	internal var fastlimit:Int64

	internal var nocwnd:Int64

	init(conv:UInt32, user:UnsafeMutableRawPointer) {
		self.conv = conv
		self.mtu = IKCP_MTU_DEF
		self.mss = mtu - IKCP_OVERHEAD
		self.state = 0

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

		self.snd_wnd = IKCP_WND_SND
		self.rcv_wnd = IKCP_WND_RCV
		self.rmt_wnd = IKCP_WND_RCV
		self.cwnd = 0
		self.probe = 0

		self.current = 0
		self.interval = IKCP_INTERVAL
		self.ts_flush = 0
		self.xmit = 0

		self.nrcv_buf = 0
		self.nsnd_buf = 0

		self.nrcv_que = 0
		self.nsnd_que = 0

		self.nodelay = 0
		self.updated = 0

		self.ts_probe = 0
		self.probe_wait = 0

		self.dead_link = IKCP_DEADLINK
		self.incr = 0

		self.snd_queue = []
		self.rcv_queue = []
		self.snd_buf = []
		self.rcv_buf = []

		self.acklist = nil
		self.ackcount = 0
		self.ackblock = 0

		self.user = user
		self.buffer = UnsafeMutablePointer<UInt8>.allocate(capacity:Int(mtu) + Int(IKCP_OVERHEAD) * 3)

		self.fastresend = 0
		self.fastlimit = Int64(IKCP_FASTACK_LIMIT)
		self.nocwnd = 0
	}
	enum Error:Swift.Error {
		/// thrown when the rcv_queue is empty
		case rcvQueueEmpty
		/// thrown when the rcv_queue has less segments than the frg value of the first segment
		case rcvQueueLessThanFrg
		/// thrown when the peeked size is greater than the input count
		case peekedSizeGreaterThanInputCount
	}
	mutating func receive(count:Int) throws -> [UInt8] {
		var recover = false
		guard rcv_queue.isEmpty == false else {
			throw Error.rcvQueueEmpty
		}
		guard count > 0 else {
			return nil
		}
		let peekedSize = try peekSize()
		guard peekedSize > count 
	}

	mutating func peekSize() throws -> Int {
		guard rcv_queue.isEmpty == false else {
			throw Error.rcvQueueEmpty
		}
		let seg = rcv_queue.first!
		guard seg.frg != 0 else {
			return Int(seg.len)
		}
		guard rcv_queue.count >= seg.frg + 1 else {
			throw Error.rcvQueueLessThanFrg
		}
		var length:Int = 0
		segLoop: for seg in rcv_queue {
			length += seg.data.count
			guard seg.frg != 0 else {
				break segLoop
			}
		}
		return length
	}
}