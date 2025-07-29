// The Swift Programming Language
// https://docs.swift.org/swift-book

import RAW
import NIO
import RAW_dh25519
import RAW_base64

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
    
    public func run() async throws {
//        let channel = try await self.connectedChannel.get()
//        try await gracefulShutdown()
//        try? await channel.close()
    }
	
	public func sendInitialPacket() throws {

        let peerPublicKeyBase64 = String(RAW_base64.encode(peerPublicKey))
        var privKeyCopy = staticPrivateKey
        let myPublicKeyBase64 = String(RAW_base64.encode(PublicKey(&privKeyCopy)))
        
        print("Peer Public Key: \(peerPublicKeyBase64)")
        print("My Public Key: \(myPublicKeyBase64)")
        
        let address = try SocketAddress(ipAddress: ipAddress, port: port)
        let peerPublicKeys = [address.description: peerPublicKey]
		// Create Channel
		let bootstrap =  DatagramBootstrap(group: group)
			.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
			.channelInitializer { channel in
				channel.pipeline.addHandlers([
				PacketHandler(logLevel:.trace),
                HandshakeHandler(privateKey:self.staticPrivateKey, peers: peerPublicKeys, logLevel:.trace),
                DataHandler(logLevel: .trace),
			])
		}

		// Start Channel
		let channel = try bootstrap.bind(host:"0.0.0.0", port:36361).wait()
		
		print("Server started successfully on \(channel.localAddress?.description ?? "unknown address")")
        
        let c: Result32 = Result32(RAW_staticbuff: try generateRandomBytes(count: 32))
        let e:[UInt8] = []
        let arr:[Result32] = try wgKDF(key: c, data: e, type: 2)
        let TIsend = arr[0]
        
        let senderIndex = try generateSecureRandomBytes(as:PeerIndex.self)
        
        let message:String = "This is a message to be encrypted"
        let messageBytes: [UInt8] = Array(message.utf8)
        var nonce_i:Result8 = Result8(RAW_native: 0)
        
        var encryptedPacket = try DataMessage.forgeDataMessage(receiverIndex: senderIndex, nonce: &nonce_i, transportKey: TIsend, plainText: messageBytes)
        var size:RAW.size_t = 0
        encryptedPacket.RAW_encode(count: &size)
        var pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        encryptedPacket.RAW_encode(dest: pointer)
        defer{
            pointer.deallocate()
        }
        let byteBuffer = Array(UnsafeBufferPointer(start: pointer, count: size))
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: byteBuffer.count)
        buffer.writeBytes(byteBuffer)
        
        let envelope = AddressedEnvelope(remoteAddress: try SocketAddress(ipAddress: ipAddress, port: port), data: buffer)
//        channel.pipeline.fireChannelRead(envelope)


		try channel.closeFuture.wait()

		print("Server closed.")
		
	}
	
	deinit {
		try? group.syncShutdownGracefully()
	}
}


