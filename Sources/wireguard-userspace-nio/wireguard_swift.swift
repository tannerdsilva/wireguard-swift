// The Swift Programming Language
// https://docs.swift.org/swift-book

import RAW
import NIO
import RAW_dh25519
import RAW_base64

/// Represents a peer on the WireGuard interface. Each peer has a unique public key assosiated with it.
public struct Peer:Sendable {
    let publicKey:PublicKey
    
    let endpoint:SocketAddress?
    let internalKeepAlive:TimeAmount?
    
    public init(publicKey: PublicKey, ipAddress:String?, port:Int?, internalKeepAlive: TimeAmount?) {
        self.publicKey = publicKey
        self.internalKeepAlive = internalKeepAlive
        
        if (ipAddress != nil && port != nil) {
            do {
                self.endpoint = try SocketAddress(ipAddress: ipAddress!, port: port!)
            } catch {
                self.endpoint = nil
            }
        } else {
            self.endpoint = nil
        }
    }
}

/// primary wireguard interface. this is how connections will be made.
public struct WGInterface:Sendable {
	
    /// The private key of the interface (owners private key)
	let staticPrivateKey:PrivateKey
    
    /// The initial configuration for peers upon interface creation
    let initialConfiguration:[Peer]
	
	private let group:MultiThreadedEventLoopGroup
	
    /// Initialize with owners `PrivateKey` and the configuration `[Peer]`
    public init(staticPrivateKey: consuming PrivateKey, initialConfiguration:[Peer] = []) throws {
		self.staticPrivateKey = staticPrivateKey
        self.initialConfiguration = initialConfiguration

        self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
		
	}
	
    /// Starts the WireGuard interface
    public func run() async throws {
        
        let peers = initialConfiguration

		let dh = DataHandler(logLevel: .trace, initialConfiguration: peers)
		let bootstrap =  DatagramBootstrap(group: group)
			.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
			.channelInitializer { channel in
				channel.pipeline.addHandlers([
				PacketHandler(logLevel:.trace),
                HandshakeHandler(privateKey:self.staticPrivateKey, logLevel:.trace),
                dh
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
        var nonce_i:Counter = Counter(RAW_native: 0)
        
        var encryptedPacket = peers[0].publicKey
        var size: RAW.size_t = 0
        encryptedPacket.RAW_encode(count: &size)

        var byteBuffer: [UInt8] = {
            let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
            defer { pointer.deallocate() }

            encryptedPacket.RAW_encode(dest: pointer)
            return Array(UnsafeBufferPointer(start: pointer, count: size))
        }()
        byteBuffer.append(contentsOf: messageBytes)
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: byteBuffer.count)
        buffer.writeBytes(byteBuffer)
        
        
        
        let envelope = AddressedEnvelope(remoteAddress: try peers[0].endpoint!, data: buffer)
        channel.pipeline.fireChannelRead(envelope)


        let asyncConsumer = dh.pendingOutgoingPackets.makeAsyncConsumer()
        while let (publicKey, data) = try await asyncConsumer.next() {
            // do something
            
        }
        
		try channel.closeFuture.wait()

		print("Server closed.")
		
	}
	
}


