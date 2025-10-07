import NIO

@available(*, deprecated, renamed:"ChannelError")
internal typealias ChannelErrors = ChannelError

internal enum ChannelError:Sendable {
	/// thrown when attempting to send a message that exceeds the configured mtu for that step in the pipeline
	case outboundMessageMTUExceeded(OutboundMessageMTUExceeded)
}

extension ChannelError {
	/// expresses a scenario where an outbound message attempted to be sent exceeds the configured mtu for that step in the pipeline.
	internal struct OutboundMessageMTUExceeded:Swift.Error, Sendable {
		internal let attemptedOutboundSize:Int
		internal let mtuLimitOutbound:Int
		internal init(attemptedOutboundSize:Int, mtuLimitOutbound:Int) {
			self.attemptedOutboundSize = attemptedOutboundSize
			self.mtuLimitOutbound = mtuLimitOutbound
		}
	}
}