// The Swift Programming Language
// https://docs.swift.org/swift-book

import RAW
import NIO
import RAW_dh25519
import RAW_base64

public typealias Key = RAW_dh25519.PublicKey

public final class WireguardInterface {
    let elg: EventLoopGroup
    let listeningPort:Int
    let staticPublicKey:PublicKey

    let connectedChannel:EventLoopFuture<Channel>
    let peerRouter:PeerRouter

    public init(loopGroupProvider:EventLoopGroup, staticPublicKey:PublicKey, listeningPort:Int? = nil) {
        self.elg = loopGroupProvider

        let lp:Int
        if let listeningPort = listeningPort {
            self.listeningPort = listeningPort
            lp = listeningPort
        } else {
            lp = Int.random(in:10000..<16000)
            self.listeningPort = lp
        }

        let pr = PeerRouter()
        self.peerRouter = pr
        self.staticPublicKey = staticPublicKey
//        self.connectedChannel = DatagramBootstrap(group:elg.next())
//            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value:1)
//            .channelInitializer({ [pr] channel in
//                return channel.pipeline.addHandler(pr)
//            }).bind(host:"0.0.0.0", port:lp)
        self.connectedChannel = DatagramBootstrap(group:elg).bind(host: "0.0.0.0", port: lp)
    }

    public func run() async throws {
//        let channel = try await self.connectedChannel.get()
//        try await gracefulShutdown()
//        try? await channel.close()
    }
}

// Handler to process incoming and outgoing data
internal final class PeerRouter:ChannelDuplexHandler {
    internal typealias InboundIn = AddressedEnvelope<ByteBuffer>
    internal typealias InboundOut = AddressedEnvelope<ByteBuffer>
    internal typealias OutboundIn = AddressedEnvelope<ByteBuffer> // receive to write
    internal typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    private var handshakeStages = [SocketAddress:Int]()
    
    internal init() {}

    internal func channelActive(context:ChannelHandlerContext) {
        
    }
    
    func channelRead(context:ChannelHandlerContext, data:NIOAny) {
        let envelope = self.unwrapInboundIn(data)
        var body = envelope.data
        
        // what kind of message is this?
        guard body.readableBytes >= 4 else {
            return
        }
//        var wgHeader = TypeHeading(RAW_staticbuff:body.readBytes(length:4)!)
//        guard wgHeader.isValid() else {
//            return
//        }
        // switch wgHeader.type {
        //     case 0x1:
                
        //     case 0x2:

        //     case 0x3:

        //     case 0x4:
        // }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error: \(error)")
        context.close(promise: nil)
    }
}

public final class WGInterface: Sendable {
    let ipAddress: String
    let port: Int
    
    let staticPrivateKey:PrivateKey
    let peerPublicKey:PublicKey
    
    let group:MultiThreadedEventLoopGroup
    
    public init(ipAddress: String, port: Int, staticPrivateKey: consuming PrivateKey, peerPublicKey: PublicKey) throws {
        self.port = port
        self.ipAddress = ipAddress

        self.peerPublicKey = peerPublicKey
        self.staticPrivateKey = staticPrivateKey

        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        
    }
    
    public func sendInitialPacket() throws {
        
        // Create Byte Payload
        let (_,_,payload) = try withUnsafePointer(to: staticPrivateKey) { p in
            try withUnsafePointer(to: peerPublicKey) { q in
                return try HandshakeInitiationMessage.forgeInitiationState(initiatorStaticPrivateKey: p, responderStaticPublicKey: q)
            }
        }
        
		let authenticatedPacket = try withUnsafePointer(to: peerPublicKey) { q in
			return try HandshakeInitiationMessage.finalizeInitiationState(responderStaticPublicKey: q, payload: payload)
		}
        
        // Create Channel
        let bootstrap =  DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandlers([
                    InputHandler(data: authenticatedPacket, ipAddress: self.ipAddress, port: self.port, privateKey: self.staticPrivateKey)
                ])
            }
        
        // Start Channel
        let channel = try bootstrap.bind(host:"0.0.0.0", port:Int.random(in:24245..<36367)).wait()

        print("Server started successfully on \(channel.localAddress?.description ?? "unknown address")")
        
        let peerPublicKeyBase64 = String(try RAW_base64.encode(peerPublicKey))
		var privKeyCopy = staticPrivateKey
        let myPublicKeyBase64 = String(try RAW_base64.encode(PublicKey(&privKeyCopy)))
        
        print("Peer Public Key: \(peerPublicKeyBase64)")
        print("My Public Key: \(myPublicKeyBase64)")
        
        // Create the addressed envolope with the destination port 
        // Write and flush to the channel
        
        try channel.closeFuture.wait()

        print("Server closed.")
        
    }
    
    
}

internal final class InputHandler: ChannelDuplexHandler, Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias InboundOut = Never

    typealias OutboundIn = Never
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    let data: HandshakeInitiationMessage.AuthenticatedPayload
    let ipAddress: String
    let port: Int
    let privateKey: PrivateKey

    init(data: HandshakeInitiationMessage.AuthenticatedPayload, ipAddress: String, port: Int, privateKey: PrivateKey) {
        self.data = data
        self.ipAddress = ipAddress
        self.port = port
        self.privateKey = privateKey
    }
    
    func channelActive(context: ChannelHandlerContext) {
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
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envolope = self.unwrapInboundIn(data)
        let buffer = envolope.data
        let authPayload = buffer.withUnsafeReadableBytes{bytebuffer in
            guard bytebuffer.count == 96 else {
                fatalError("Wrong length \(bytebuffer.count)")
            }
            for i in 0..<bytebuffer.count {
                print("Byte \(i): \(bytebuffer[i])")
            }
            return HandshakeResponseMessage.AuthenticatedPayload(RAW_decode:bytebuffer.baseAddress!, count:96)
        }
        
//        let validation = try! withUnsafePointer(to: privateKey) { privateKey in
//            try! withUnsafePointer(to: authPayload!) { authPayload in
//                try! HandshakeResponseMessage.validateResponseMessage(authPayload, initiatorStaticPrivateKey: privateKey, initiatorEphemeralPrivateKey: <#T##UnsafePointer<PrivateKey>#>)
//            }
//        }
        
        fatalError("Successss")
        let remoteAddress = envolope.remoteAddress
        
        let str = buffer.getString(at: 0, length: buffer.readableBytes) ?? ""
        
        let gstring = "\u{001B}[32m" + str + "\u{001B}[0m"
        var outBuff = context.channel.allocator.buffer(capacity: gstring.utf8.count)
        outBuff.writeString(gstring)
        
        let responseEnvelope = AddressedEnvelope(remoteAddress: remoteAddress, data: outBuff)
        context.writeAndFlush(self.wrapOutboundOut(responseEnvelope), promise: nil)
    }
}

internal struct HandshakeHandler {
    
}
