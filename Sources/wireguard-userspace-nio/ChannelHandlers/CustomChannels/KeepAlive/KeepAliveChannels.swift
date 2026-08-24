import NIO
import Logging

/// A custom channel set that sends keep-alive packets and drops all data. The
/// keep-alive channels exist solely to send empty keep-alive packets, keeping
/// the WireGuard interface handshaking with its peers.
///
/// - Head Channel: Sends a keep-alive packet for each peer according to the peer's
///   keep-alive time configuration.
/// - Body Channels: None
/// - Tail Channel: Drops all incoming or outgoing packets.
public struct KeepAlive: CustomChannels {
	
	/// The head channel, which sends keep-alive packets.
	public var head: HeadChannel
	
	/// The tail channel, which drops all packets.
	public var tail: TailChannel
	
	/// The body channels, which process data between the head and tail channels.
	public var body: BodyChannels
	
	/// The head channel type for these custom channels.
	public typealias HeadChannel = KeepAliveHandler
	
	/// The tail channel type for these custom channels.
	public typealias TailChannel = DropAllHandler
	
	/// The body channel type for these custom channels.
	public typealias BodyChannels = [any ChannelDuplexHandler & Sendable]
	
	/// The argument type passed to the custom channels initializer.
	public typealias ArgumentType = (peers:[PeerInfo], loglevel:Logger.Level)
	
	/// Creates a keep-alive channel set.
	/// - Parameters:
	///   - env: The peers to keep alive and the shared log level.
	///   - mtuLimits: MTU limits; unused by these channels.
	public init(_ env: ArgumentType, mtuLimits:inout MTULimits) {
		head = KeepAliveHandler(peers: env.peers, logLevel: env.loglevel)
		tail = DropAllHandler(logLevel: env.loglevel)
		body = []
	}
}
