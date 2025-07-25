import NIO
import Logging
import RAW_dh25519

struct HandshakeInitiationInvoke {
	let endpoint:SocketAddress
	let publicKey:PublicKey
}

final class HandshakeInvoker:ChannelOutboundHandler, RemovableChannelHandler, Sendable {
	typealias OutboundIn = Never
	typealias OutboundOut = HandshakeInitiationInvoke

	private let logger:Logger

	let invokeToSend:HandshakeInitiationInvoke

	init(invoke:HandshakeInitiationInvoke, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger
		invokeToSend = invoke
	}

	func handlerAdded(context:ChannelHandlerContext) {
		logger.trace("added to pipeline, sending handshake initiation invoke to peer", metadata:["peer_endpoint":"\(invokeToSend.endpoint.description)", "peer_public_key":"\(invokeToSend.publicKey)"])
        context.writeAndFlush(wrapOutboundOut(invokeToSend), promise:nil)
		context.pipeline.removeHandler(self).whenComplete { [l = logger] _ in
			l.trace("removed from pipeline")
		}
	}
}