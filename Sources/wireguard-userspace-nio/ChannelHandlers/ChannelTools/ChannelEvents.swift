import NIO
internal enum InboundEvent {
	case peerConfigUpdate([any PeerInformation], EventLoopPromise<Void>)
}
