extension KCPControlBlock {
	/// - *purpose*: window-probe state
	/// - *read/written when*: written when we receive a segment with rmt_wnd == 0. cleared when we receive a segment with rmt_wnd > 0
	/// - *how it affects ack processing*: triggers a probe packet after `probe_wait` ms so the remote can advertise a larger window 
	internal struct ProbeInfo:Sendable {
		/// flags to indicate whether we need to send a window probe
		internal var probe:UInt32 = 0
		/// timestamp of the next scheduled probe
		internal var ts_probe:UInt64 = 0
		/// time to wait before probing again
		internal var probe_wait:UInt64 = 0
	}
}
