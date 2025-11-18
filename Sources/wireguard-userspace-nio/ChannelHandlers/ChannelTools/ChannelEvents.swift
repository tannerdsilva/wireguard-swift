import NIO
internal enum InboundEvent {
	case peerConfigUpdate([PeerInfo], EventLoopPromise<Void>)
}
