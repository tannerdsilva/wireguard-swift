extension KCPControlBlock {
	/// - *purpose*: round trip time estimator and retransmission timing variables
	/// - *read/written when*: updated when an ack is received for a segment that was sent
	/// - *how it affects ack processing*: the computed rx_rto determines how long we wait before retransmitting a segment that is still in sendBuffer and whose `sn < snd_una`
	internal struct RoundTripTimeInfo:Sendable {
		/// the smoothed round trip time
		internal var rx_srtt:UInt32 = 0
		/// the smoothed round trip time variance
		internal var rx_rttval:UInt32 = 0
		/// the current retransmission timeout
		internal var rx_rto:UInt32
		/// the minimum retransmission timeout
		internal let rx_minrto:UInt32
		/// the maximum retransmission timeout
		internal let rx_maxrto:UInt32
		
		/// initialize a new RoundTripTimeInfo structure.
		/// - parameters:
		/// 	- rx_rto: initial retransmission timeout.
		/// 		- default value: `IKCP_RTO_DEF`
		/// 	- rx_minrto: minimum retransmission timeout.
		/// 		- default value: `IKCP_RTO_MIN`
		/// 	- rx_maxrto: maximum retransmission timeout.
		/// 		- default value: `IKCP_RTO_MAX`
		internal init(rx_rto:UInt32 = IKCP_RTO_DEF, rx_minrto:UInt32 = IKCP_RTO_MIN, rx_maxrto:UInt32 = IKCP_RTO_MAX) {
			self.rx_rto = rx_rto
			self.rx_minrto = rx_minrto
			self.rx_maxrto = rx_maxrto
		}
	}
}