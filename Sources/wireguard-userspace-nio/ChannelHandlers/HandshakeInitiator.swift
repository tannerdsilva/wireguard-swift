import NIO
import RAW_dh25519

struct HandshakeInitiationInvoke {
	let endpoint: SocketAddress
	let publicKey: PublicKey
}

final class HandshakeInvoker:ChannelOutboundHandler, RemovableChannelHandler, Sendable {
	typealias OutboundIn = Never
	typealias OutboundOut = HandshakeInitiationInvoke

	let invokeToSend: HandshakeInitiationInvoke

	init(invoke: HandshakeInitiationInvoke) {
		self.invokeToSend = invoke
	}

	func handlerAdded(context: ChannelHandlerContext) {
        context.writeAndFlush(self.wrapOutboundOut(invokeToSend)).whenComplete { _ in
			print("Handshake initiation sent to \(self.invokeToSend.endpoint)")
		}
	}
}