extension KCPControlBlock {
	/// - *purpose*: congestion window state
	/// - *read/written when*: written when acks arrive (`cwnd` grows) and when a timeout occurs (`cwnd` -> `ssthresh/1`)
	/// - *how it affects ack processing*: limits how many new data segments may be placed on the wire (cwnd + rmt_wnd). If cwnd is exhausted we must hold back new writes until ACKs free space
	internal struct CongestionWindowInfo:Sendable {
		/// the current congestion window
		internal var cwnd:UInt32 = 0
		/// the current increment value
		internal var incr:UInt32 = 0
		/// the slow start threshold
		internal var ssthresh:UInt32 = IKCP_THRESH_INIT
	}
}