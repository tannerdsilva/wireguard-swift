/// used to clearly define the MTU limits for a pipeline member of a nio pipeline.
public struct MTULimits:Sendable {
	/// the maximum transmission unit for inbound packets coming from the kernel to the wireguard nio interface. this is typically 1420 bytes for a standard wireguard interface.
	public let mtuInboundIn:Int
	/// the maximum transmission unit for outbound packets going from the wireguard nio interface to the kernel. this is typically 1420 bytes for a standard wireguard interface.
	public let mtuOutboundOut:Int
	/// the maximum transmission unit for outbound packets that are being written to the wireguard nio interface. this is typically the normal MTU sub the wireguard overhead.
	public let mtuOutboundIn:Int
	/// the maximum transmission unit for inbound packets coming from the kernel to the wireguard nio interface after any processing has been done. this is typically the normal MTU sub the wireguard overhead.
	public let mtuInboundOut:Int
	
	/// creates a new MTULimits struct with the same MTU for all directions.
	/// - parameter mtu: the MTU value to use for all directions.
	public init(
		bidirectional mtu:Int
	) {
		self.mtuInboundIn = mtu
		self.mtuOutboundOut = mtu
		self.mtuOutboundIn = mtu
		self.mtuInboundOut = mtu
	}

	/// creates a new MTULimits struct with the specified MTU values.
	public init(
		mtuInboundIn:Int,
		mtuOutboundOut:Int,
		mtuOutboundIn:Int,
		mtuInboundOut:Int
	) {
		self.mtuInboundIn = mtuInboundIn
		self.mtuOutboundOut = mtuOutboundOut
		self.mtuOutboundIn = mtuOutboundIn
		self.mtuInboundOut = mtuInboundOut
	}
}
