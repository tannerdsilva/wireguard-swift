/// Defines the MTU limits for a pipeline member of a NIO pipeline.
public struct MTULimits:Sendable {
	/// The maximum transmission unit for inbound packets coming from the kernel to
	/// the WireGuard NIO interface. This is typically 1420 bytes for a standard
	/// WireGuard interface.
	public let mtuInboundIn:Int
	/// The maximum transmission unit for outbound packets going from the WireGuard
	/// NIO interface to the kernel. This is typically 1420 bytes for a standard
	/// WireGuard interface.
	public let mtuOutboundOut:Int
	/// The maximum transmission unit for outbound packets written to the WireGuard
	/// NIO interface. This is typically the normal MTU minus the WireGuard overhead.
	public let mtuOutboundIn:Int
	/// The maximum transmission unit for inbound packets coming from the kernel to
	/// the WireGuard NIO interface after processing. This is typically the normal
	/// MTU minus the WireGuard overhead.
	public let mtuInboundOut:Int

	/// Creates a new `MTULimits` with the same MTU for all directions.
	/// - Parameter mtu: The MTU value to use for all directions.
	public init(
		bidirectional mtu:Int
	) {
		self.mtuInboundIn = mtu
		self.mtuOutboundOut = mtu
		self.mtuOutboundIn = mtu
		self.mtuInboundOut = mtu
	}

	/// Creates a new `MTULimits` with the specified MTU values.
	/// - Parameters:
	///   - mtuInboundIn: The maximum inbound MTU from the kernel.
	///   - mtuOutboundOut: The maximum outbound MTU to the kernel.
	///   - mtuOutboundIn: The maximum outbound MTU written to the interface.
	///   - mtuInboundOut: The maximum inbound MTU after processing.
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
