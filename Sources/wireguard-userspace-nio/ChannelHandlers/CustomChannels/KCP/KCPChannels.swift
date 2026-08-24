import NIO
import Logging
import RAW
import RAW_dh25519

/// A set of custom channels implementing a modified version of KCP, a UDP wrapper
/// providing reliable, in-order packet delivery. Highly inspired by the original
/// C implementation (see https://github.com/skywind3000/kcp for more information on KCP).
///
/// - Head Channel: `KCPSegment.Handler`, which combines and splits KCP segments to and from a single MTU data packet.
/// - Body Channels: `KCPControlBlock.Handler`, which takes raw data from the tail channel and wraps it into a KCP segment with its associated segment header.
/// - Tail Channel: `SplicerHandler`, which splices outbound data according to the MTU of the pipeline.
public struct KCPChannels: CustomChannels {
	
	/// The head channel for these custom channels.
	public let head: HeadChannel
	
	/// The tail channel for these custom channels.
	public var tail: TailChannel
	
	/// The body channels for these custom channels.
	public var body: BodyChannels
	
	/// The head channel type for these custom channels.
	public typealias HeadChannel = KCPSegment.Handler
	
	/// The tail channel type for these custom channels.
	public typealias TailChannel = SplicerHandler
	
	/// The body channel type for these custom channels.
	public typealias BodyChannels = [any ChannelDuplexHandler & Sendable]
	
	/// The argument type passed to the custom channels initializer.
	public typealias ArgumentType = (privateKey:MemoryGuarded<PrivateKey>, loglevel:Logger.Level)
	
	/// Creates a set of KCP custom channels.
	/// - Parameters:
	///   - env: The interface's private key and the shared log level.
	///   - mtuLimits: The MTU limits used to configure the created channels.
	public init(_ env: ArgumentType, mtuLimits:inout MTULimits) {
		head = KCPSegment.Handler(privateKey:env.privateKey, mtu:&mtuLimits, logLevel:env.loglevel)
		body = [KCPControlBlock.Handler(key:env.privateKey, mtu:&mtuLimits, logLevel:env.loglevel)]
		tail = SplicerHandler(logLevel:env.loglevel, spliceByteLength: 50_000)
	}
}
