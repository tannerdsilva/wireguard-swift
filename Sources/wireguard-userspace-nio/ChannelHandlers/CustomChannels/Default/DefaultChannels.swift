import NIO
import Logging

/// A set of default custom channels with no body channels.
///
/// The head channel passes inbound and outbound data through unchanged, and the
/// tail channel splices outbound data to the MTU of the pipeline.
public struct DefaultChannels: CustomChannels {
	
	/// The head channel, through which inbound and outbound data travels first.
	public var head: HeadChannel
	
	/// The tail channel, through which inbound and outbound data travels last.
	public var tail: TailChannel
	
	/// The body channels, which process data between the head and tail channels.
	public var body: BodyChannels
	
	/// The head channel type for these custom channels.
	public typealias HeadChannel = DefaultHeadChannelHandler
	
	/// The tail channel type for these custom channels.
	public typealias TailChannel = SplicerHandler
	
	/// The body channel type for these custom channels.
	public typealias BodyChannels = [any ChannelDuplexHandler & Sendable]
	
	/// The argument type passed to the custom channels initializer.
	public typealias ArgumentType = Logger.Level
	
	/// Creates a set of default custom channels.
	/// - Parameters:
	///   - env: The log level shared by the created channels.
	///   - mtuLimits: The MTU limits used to configure the tail channel.
	public init(_ env: ArgumentType, mtuLimits:inout MTULimits) {
		head = DefaultHeadChannelHandler(logLevel: env)
		tail = SplicerHandler(logLevel: env, spliceByteLength: mtuLimits.mtuOutboundIn)
		body = []
	}
}
