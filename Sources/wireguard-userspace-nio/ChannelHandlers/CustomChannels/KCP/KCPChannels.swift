import NIO
import Logging
import RAW
import RAW_dh25519

/// Struct defining the set of KCP CustomChannels.
/// KCP is a UDP wrapper that provides guaranteed, in-order packet delivery to the UDP protocol.
/// See https://github.com/skywind3000/kcp for more information on KCP.
///
/// This set of custom channels implements a modified version of KCP highly inspired by the original C code.
///
/// - Head Channel: KCP Segment Handler for combining/splicing KCP Segments into/from a single MTU data packet.
/// - Body Channels: KCP Control Block handler used for taking raw data from the Tail Channel and wrapping it into a KCP Segment with it's associated Segment header.
/// - Tail Channel: Splicer Handler which splices outbound data according to the MTU of the pipeline.
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
