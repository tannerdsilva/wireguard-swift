import NIO
import Logging

/// Struct defining the set of default CustomChannels.
/// Use this struct as a template for any new struct conforming to CustomChannels
///
/// - Head Channel: Default channel that passes inbound/outbound data to the next handler
/// - Body Channels: None
/// - Tail Channel: Splicer Handler which splices outbound data according to the MTU of the pipeline.
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
