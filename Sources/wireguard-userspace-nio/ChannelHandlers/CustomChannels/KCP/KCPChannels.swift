import NIO
import Logging
import RAW
import RAW_dh25519

public struct KCPChannels: CustomChannels {
	
	public var head: HeadChannel
	
	public var tail: TailChannel
	
	public var body: BodyChannels
	
	public typealias HeadChannel = KCPSegment.Handler
	
	public typealias TailChannel = SplicerHandler
	
	public typealias BodyChannels = [any ChannelDuplexHandler & Sendable]
	
	public typealias ArgumentType = (privateKey:MemoryGuarded<PrivateKey>, loglevel:Logger.Level)
	
	public init(_ env: ArgumentType, mtuLimits:inout MTULimits) {
		head = KCPSegment.Handler(privateKey:env.privateKey, mtu:&mtuLimits, logLevel:env.loglevel)
		body = [KCPControlBlock.Handler(key:env.privateKey, mtu:&mtuLimits, logLevel:env.loglevel)]
		tail = SplicerHandler(logLevel:env.loglevel, spliceByteLength: 50_000)
	}
}
