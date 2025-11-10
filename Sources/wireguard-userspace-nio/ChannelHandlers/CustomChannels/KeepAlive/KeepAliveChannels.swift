import NIO
import Logging

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
