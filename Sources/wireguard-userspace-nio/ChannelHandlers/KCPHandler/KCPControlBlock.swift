public struct KCPControlBlock {
	/// conversation id
	public var conv:UInt32
	/// maximum transmission unit: the largest udp packet accepted
	public var mtu:UInt32
	/// maximum segment size: largest amount of data per segment
	public var mss:UInt32
	
	/// earliest unacknowledged segment
	public var snd_una:UInt32
	/// next segment number to send
	public var snd_nxt:UInt32
	/// next expected segment number from peer
	public var rcv_nxt:UInt32

	/// timestamp of the most recent packet received (used for RTT calculation)
	public var ts_recent:UInt32
	public var ts_lastack:UInt32	// Timestamp of the last ACK sent
	public var ssthresh:UInt32	// Slow start theshold

	public var rx_rttval:Int32	// Smoothed RTT Variance
	public var rx_srtt:Int32	// Smoothed RTT
	public var rx_rto:Int32

	// Retransmission timeout (dynamically calculated)
	public var rx_minrto:Int32	// Minimum RTO allowed
	public var rx_maxrto:Int32

	public var snd_wnd:UInt32		// Sender's Window: How many unacked segments willing to send
	public var rcv_wnd:UInt32		// Receivers Window: How many segments we can accept
	public var rmt_wnd:UInt32		// Remote's advertised receive window
	public var cwnd:UInt32		// Congestion Window
	public var probe:UInt32		// Flags for window probing

	public var current:UInt32
	public var interval:UInt32
	public var ts_flush:UInt32
	public var xmit:UInt32		// Total number of transmissions

	public var nodelay:UInt32		// 1 for nodelay mode

	public var ts_probe:UInt32	// Next scheduled probe time
	public var probe_wait:UInt32	// Time to wait before probing again

	public var dead_link:UInt32	// Max number of retransmits before considering the link dead
	public var incr:UInt32

	// public var snd_queue = LinkedList<KCPSegment>()		// user data waiting to be segmented and sent out
	// public var rcv_queue = LinkedList<KCPSegment>()		// Fully reassembled segments ready to return to application
	// public var snd_buf = LinkedList<KCPSegment>()			// Segments sent and waiting to be ACKed
	// public var rcv_buf = LinkedList<KCPSegment>()			// Segments received out of oder and waiting to be reassembled
	
	/// acklist is nil when ackcount == 0. variable is safe to access any time ackcount > 0
	private var acklist:UnsafeMutableBufferPointer<UInt32>!
	public var ackcount:UInt32
	public var ackblock:UInt32
}