/// used to clearly define the MTU limits for a pipeline member of a nio pipeline.
internal struct MTULimits {
	/// the maximum transmission unit for inbound packets coming from the kernel to the wireguard nio interface. this is typically 1420 bytes for a standard wireguard interface.
	internal let mtuInboundIn:UInt16
	/// the maximum transmission unit for outbound packets going from the wireguard nio interface to the kernel. this is typically 1420 bytes for a standard wireguard interface.
	internal let mtuOutboundOut:UInt16
	/// the maximum transmission unit for outbound packets that are being written to the wireguard nio interface. this is typically the normal MTU sub the wireguard overhead.
	internal let mtuOutboundIn:UInt16

	/// creates a new MTULimits struct with the specified MTU values.
	internal init(mtuInboundIn:UInt16, mtuOutboundOut:UInt16, mtuOutboundIn:UInt16) {
		self.mtuInboundIn = mtuInboundIn
		self.mtuOutboundOut = mtuOutboundOut
		self.mtuOutboundIn = mtuOutboundIn
	}
}