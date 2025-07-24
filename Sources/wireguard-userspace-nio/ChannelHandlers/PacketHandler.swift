import NIO

internal enum PacketType {
    case handshakeInitiation(SocketAddress, HandshakeInitiationMessage.AuthenticatedPayload)
    case handshakeResponse(SocketAddress, HandshakeResponseMessage.AuthenticatedPayload)
    //case Cookie()
    //case DataPacket()
}

internal final class PacketHandler: ChannelDuplexHandler, Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias InboundOut = PacketType
    
    typealias OutboundIn = PacketType
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envolope = self.unwrapInboundIn(data)
        let buffer = envolope.data
        let remoteAddress = envolope.remoteAddress
        
        /// Find the header type of packet
        let headerType = buffer.withUnsafeReadableBytes{bytebuffer in
            return bytebuffer[0]
        }
        
        /// Parse packet depending on the header type
        switch headerType {
        case 0x1:
            let authPayload = buffer.withUnsafeReadableBytes{bytebuffer in
                guard bytebuffer.count == 148 else {
                    fatalError("Wrong length \(bytebuffer.count)")
                }
                return HandshakeInitiationMessage.AuthenticatedPayload(RAW_decode:bytebuffer.baseAddress!, count:148)
            }
            let packet: PacketType = .handshakeInitiation(remoteAddress, authPayload!)
            context.fireChannelRead(wrapInboundOut(packet))
        
        case 0x2:
            let authPayload = buffer.withUnsafeReadableBytes{bytebuffer in
                guard bytebuffer.count == 92 else {
                    fatalError("Wrong length \(bytebuffer.count)")
                }
                return HandshakeResponseMessage.AuthenticatedPayload(RAW_decode:bytebuffer.baseAddress!, count:92)
            }
            let packet: PacketType = .handshakeResponse(remoteAddress, authPayload!)
            context.fireChannelRead(wrapInboundOut(packet))
        
        default:
            print("Not supported type")
        }
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        /// Handles receiving Outbound Packets and sending out a UDP packet to the remote address
        let packet = self.unwrapOutboundIn(data)

		let destinationEndpoint: SocketAddress
		let sendBuffer: ByteBuffer
        switch packet {
            case let .handshakeInitiation(endpoint, payload):
				var buffer = context.channel.allocator.buffer(capacity: MemoryLayout<HandshakeInitiationMessage.AuthenticatedPayload>.size)
				buffer.writeBytes(payload)
				destinationEndpoint = endpoint
				sendBuffer = buffer
			case let .handshakeResponse(endpoint, payload):
				var buffer = context.channel.allocator.buffer(capacity: MemoryLayout<HandshakeResponseMessage.AuthenticatedPayload>.size)
				buffer.writeBytes(payload)
				destinationEndpoint = endpoint
				sendBuffer = buffer
		}

        let processedEnvelope = AddressedEnvelope(remoteAddress: destinationEndpoint, data: sendBuffer)

        context.writeAndFlush(self.wrapOutboundOut(processedEnvelope), promise:promise)
    }
}
