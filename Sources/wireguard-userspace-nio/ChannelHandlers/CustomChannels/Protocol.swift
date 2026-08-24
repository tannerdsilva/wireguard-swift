import NIO

/// The protocol for the head custom channel communicating with the WireguardDuplexHandler. Ensures the Inbound and Outbound types match.
public protocol PeerAssociatedHeadHandler:Sendable, ChannelDuplexHandler where OutboundOut == PeerAssociated<ByteBuffer>, InboundIn == PeerAssociated<ByteBuffer> {}
/// The protocol for the tail custom channel communicating with the DataHandoffHandler. Ensures the Inbound and Outbound types match.
public protocol PeerAssociatedTailHandler:Sendable, ChannelDuplexHandler where OutboundIn == PeerAssociated<ByteBuffer>, InboundOut == PeerAssociated<ByteBuffer> {}

/// Defines the set of custom channels inbetween data encryption and data handoff.
///
/// The HeadChannel, TailChannel, and BodyChannels all need to conform to ChannelDuplexHandler.
/// The HeadChannel is a special ChannelDuplexHandler where the OutboundOut and InboundIn are PeerAssociated<ByteBuffer>'s.
/// The TailChannel is a special ChannelDuplexHandler where the OutboundIn and InboundOut are PeerAssociated<ByteBuffer>'s.
///
/// The channels connect in the following order: HeadChannel - > BodyChannels[0] - > ... - > BodyChannels[n-1] - > TailChannel
///
/// It is the responsibility of the user to ensure that the Inbound and Outbound variables align within these custom channels.
/// See `KCPChannels`, `KeepAlive`, and `DefaultChannels` for implementations of the protocol.
public protocol CustomChannels:Sendable {
	/// The head channel type.
	associatedtype HeadChannel:PeerAssociatedHeadHandler
	/// The tail channel type.
	associatedtype TailChannel:PeerAssociatedTailHandler
	/// The body channel type.
	associatedtype BodyChannels:Sequence where BodyChannels.Element == any ChannelDuplexHandler & Sendable
	/// The type of argument passed to `init(_:mtuLimits:)`.
	associatedtype ArgumentType
	
	/// The head channel, through which inbound and outbound data travels first.
	var head:HeadChannel { get }
	/// The tail channel, through which inbound and outbound data travels last.
	var tail:TailChannel { get }
	/// The body channels, which process data between the head and tail channels.
	var body:BodyChannels { get }
	/// Creates a set of custom channels.
	/// - Parameters:
	///   - env: The argument the concrete channel set requires.
	///   - mtuLimits: The MTU limits used to configure the channels.
	init(_ env:ArgumentType, mtuLimits:inout MTULimits)
}
