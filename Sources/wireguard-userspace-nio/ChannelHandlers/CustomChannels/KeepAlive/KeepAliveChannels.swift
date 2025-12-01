import NIO
import Logging

/// Struct defining the set of keep alive CustomChannels.
/// The keep alive channels solely exist to send empty keep alive packets to keep the WireGuard interface handshaking with it's peers.
///
/// - Head Channel: Sends a keep alive packet for each peer according to the peers keep alive time configuration.
/// - Body Channels: None
/// - Tail Channel: Drops all incoming or outgoing packets.
public struct KeepAlive: CustomChannels {
	
	public var head: HeadChannel
	
	public var tail: TailChannel
	
	public var body: BodyChannels
	
	public typealias HeadChannel = KeepAliveHandler
	
	public typealias TailChannel = DropAllHandler
	
	public typealias BodyChannels = [any ChannelDuplexHandler & Sendable]
	
	public typealias ArgumentType = (peers:[PeerInfo], loglevel:Logger.Level)
	
	public init(_ env: ArgumentType, mtuLimits:inout MTULimits) {
		head = KeepAliveHandler(peers: env.peers, logLevel: env.loglevel)
		tail = DropAllHandler(logLevel: env.loglevel)
		body = []
	}
}
