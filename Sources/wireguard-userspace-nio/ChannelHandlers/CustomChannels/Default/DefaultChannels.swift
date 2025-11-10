import NIO
import Logging

public struct DefaultChannels: CustomChannels {
	
	public var head: HeadChannel
	
	public var tail: TailChannel
	
	public var body: BodyChannels
	
	public typealias HeadChannel = DefaultHeadChannel
	
	public typealias TailChannel = SplicerHandler
	
	public typealias BodyChannels = [any ChannelDuplexHandler & Sendable]
	
	public typealias ArgumentType = Logger.Level
	
	public init(_ env: ArgumentType, mtuLimits:inout MTULimits) {
		head = DefaultHeadChannel(logLevel: env)
		tail = SplicerHandler(logLevel: env, spliceByteLength: mtuLimits.mtuOutboundIn)
		body = []
	}
}
