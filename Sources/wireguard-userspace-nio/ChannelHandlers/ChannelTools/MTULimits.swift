/// used to clearly define the MTU limits for a pipeline member of a nio pipeline.
internal struct MTULimits:Sendable {
	/// the maximum transmission unit for inbound packets coming from the kernel to the wireguard nio interface. this is typically 1420 bytes for a standard wireguard interface.
	internal let mtuInboundIn:Int
	/// the maximum transmission unit for outbound packets going from the wireguard nio interface to the kernel. this is typically 1420 bytes for a standard wireguard interface.
	internal let mtuOutboundOut:Int
	/// the maximum transmission unit for outbound packets that are being written to the wireguard nio interface. this is typically the normal MTU sub the wireguard overhead.
	internal let mtuOutboundIn:Int
	/// the maximum transmission unit for inbound packets coming from the kernel to the wireguard nio interface after any processing has been done. this is typically the normal MTU sub the wireguard overhead.
	internal let mtuInboundOut:Int
	
	/// creates a new MTULimits struct with the same MTU for all directions.
	/// - parameter mtu: the MTU value to use for all directions.
	internal init(bidirectional mtu:Int) {
		self.mtuInboundIn = mtu
		self.mtuOutboundOut = mtu
		self.mtuOutboundIn = mtu
		self.mtuInboundOut = mtu
	}

	/// creates a new MTULimits struct with the specified MTU values.
	internal init(mtuInboundIn:Int, mtuOutboundOut:Int, mtuOutboundIn:Int, mtuInboundOut:Int) {
		self.mtuInboundIn = mtuInboundIn
		self.mtuOutboundOut = mtuOutboundOut
		self.mtuOutboundIn = mtuOutboundIn
		self.mtuInboundOut = mtuInboundOut
	}
}