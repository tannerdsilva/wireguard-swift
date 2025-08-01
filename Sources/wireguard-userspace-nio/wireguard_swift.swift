// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
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
public actor WGInterface:Sendable {
	
    /// The private key of the interface (owners private key)
	let staticPrivateKey:PrivateKey
    
    /// The initial configuration for peers upon interface creation
    let initialConfiguration:[Peer]
    
    /// Data handler channel
    let dh:DataHandler
    
    /// Data channel
    var channel:Channel? = nil
	
	private let group:MultiThreadedEventLoopGroup
	
    /// Initialize with owners `PrivateKey` and the configuration `[Peer]`
    public init(staticPrivateKey: consuming PrivateKey, initialConfiguration:[Peer] = []) throws {
		self.staticPrivateKey = staticPrivateKey
        self.initialConfiguration = initialConfiguration

        self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.dh = DataHandler(logLevel: .trace, initialConfiguration: initialConfiguration)
	}
	
    /// Starts the WireGuard interface
    public func run() async throws {
        let hs = HandshakeHandler(privateKey:self.staticPrivateKey, logLevel:.trace)
		let bootstrap =  DatagramBootstrap(group: group)
			.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
			.channelInitializer { channel in
				channel.pipeline.addHandlers([
				PacketHandler(logLevel:.trace),
                hs,
                self.dh
			])
		}

		// Start Channel
        do {
            channel = try bootstrap.bind(host:"0.0.0.0", port:36361).wait()
        } catch {
            throw POSIXError(.ECONNREFUSED)
        }
		
		print("Server started successfully on \(channel!.localAddress?.description ?? "unknown address")")
        
        let asyncConsumer = dh.pendingOutgoingPackets.makeAsyncConsumer()
        while let (publicKey, data) = try await asyncConsumer.next() {
            // do something
            
        }
        
		try channel!.closeFuture.wait()

		print("Server closed.")
		
	}
    
    public func write(publicKey: PublicKey, data:[UInt8]) async throws {
        guard let channel = channel else {
            print("Channel not yet established. Use run() to start the channel")
            return
        }
        let peers = dh.getConfiguration()
        
        channel.pipeline.writeAndFlush(InterfaceInstruction.encryptAndTransmit(publicKey, data), promise: nil)
    }
    
    public func addPeer(_ peer: Peer) {
        dh.addPeer(peer: peer)
    }
    
    public func removePeer(_ peer: Peer) {
        dh.removePeer(peer: peer)
    }
	
}


