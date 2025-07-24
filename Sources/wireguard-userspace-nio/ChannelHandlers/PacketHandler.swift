import NIO

internal enum PacketType {
    case HandshakeInitiation(SocketAddress, HandshakeInitiationMessage.AuthenticatedPayload)
    case HandshakeResponse(SocketAddress, HandshakeResponseMessage.AuthenticatedPayload)
    //case Cookie()
    //case DataPacket()
}

internal final class PacketHandler: ChannelDuplexHandler {
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
            let packet: PacketType = .HandshakeInitiation(remoteAddress, authPayload!)
            context.fireChannelRead(wrapInboundOut(packet))
        
        case 0x2:
            let authPayload = buffer.withUnsafeReadableBytes{bytebuffer in
                guard bytebuffer.count == 92 else {
                    fatalError("Wrong length \(bytebuffer.count)")
                }
                return HandshakeResponseMessage.AuthenticatedPayload(RAW_decode:bytebuffer.baseAddress!, count:92)
            }
            let packet: PacketType = .HandshakeResponse(remoteAddress, authPayload!)
            context.fireChannelRead(wrapInboundOut(packet))
        
        default:
            print("Not supported type")
        }
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        /// Handles receiving Outbound Packets and sending out a UDP packet to the remote address
        let packet = self.unwrapOutboundIn(data)

        // Process the data before sending
        var buffer = envelope.data
        buffer.writeString("Processed: ")
        
        switch packet {
            
        }

        let processedEnvelope = AddressedEnvelope(remoteAddress: packet.0, data: buffer)

        // Pass down the processed data
        context.write(self.wrapOutboundOut(processedEnvelope), promise: promise)
    }
}


var allocated = context.channel.allocator.buffer(capacity:MemoryLayout<HandshakeInitiationMessage.AuthenticatedPayload>.size)
allocated.writeBytes(data)
allocated.withUnsafeReadableBytes { bytes in
    for i in 0..<bytes.count {
        print("Byte \(i): \(bytes[i])")
    }
}
let envolope = try! AddressedEnvelope(remoteAddress: SocketAddress(ipAddress: ipAddress, port: port), data: allocated)
let out = self.wrapOutboundOut(envolope)
var promise = context.eventLoop.makePromise(of: Void.self)
promise.futureResult.whenSuccess {
    print("Promise completed")
}
context.writeAndFlush(out, promise: promise)
