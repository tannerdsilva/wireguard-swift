import NIO
import RAW_dh25519

internal final class HandshakeHandler: ChannelDuplexHandler {
    typealias InboundIn = PacketType
    typealias InboundOut = PacketType
    
    typealias OutboundIn = Never
    typealias OutboundOut = PacketType
    
    let responderPrivateKey: UnsafePointer<PrivateKey>
    
    init(privateKey: UnsafePointer<PrivateKey>) {
        self.responderPrivateKey = privateKey
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        /// Handles Handshake Packets, else passes them down
        let packet = self.unwrapInboundIn(data)
        
        switch packet {
            case var .handshakeInitiation(endpoint, payload):
                /// Reads initiation payload and validates it.
                /// Once validated, sends a response packet
                var val = try! HandshakeInitiationMessage.validateInitiationMessage(&payload, responderStaticPrivateKey: responderPrivateKey)
                var sharedKey = Result32(RAW_staticbuff:Result32.RAW_staticbuff_zeroed())
                var response = try! HandshakeResponseMessage.forgeResponseState(senderPeerIndex: payload.payload.initiatorPeerIndex, initiatorStaticPublicKey: &val.initPublicKey, initiatorEphemeralPublicKey: payload.payload.ephemeral, preSharedKey: sharedKey)
                let authResponse = try! HandshakeResponseMessage.finalizeResponseState(initiatorStaticPublicKey: &val.initPublicKey, payload: response.payload)
                let packet: PacketType = .handshakeResponse(endpoint, authResponse)
                context.writeAndFlush(self.wrapOutboundOut(packet), promise: nil)
                
            case let .handshakeResponse(endpoint, payload):
                /// Reads response packet and validates it.
                /// Once validated, updates keys for data encryption (NEEDS COMPLETION)
                print("nothing")
            default:
                context.fireChannelRead(wrapInboundOut(packet))
        }
        
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        /// Handles receiving Outbound Packets and sending out a UDP packet to the remote address
        
    }
}
