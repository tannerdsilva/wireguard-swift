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
	associatedtype HeadChannel:PeerAssociatedHeadHandler
	associatedtype TailChannel:PeerAssociatedTailHandler
	associatedtype BodyChannels:Sequence where BodyChannels.Element == any ChannelDuplexHandler & Sendable
	associatedtype ArgumentType
	
	var head:HeadChannel { get }
	var tail:TailChannel { get }
	var body:BodyChannels { get }
	init(_ env:ArgumentType, mtuLimits:inout MTULimits)
}
