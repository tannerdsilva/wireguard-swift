// The Swift Programming Language
// https://docs.swift.org/swift-book

import RAW
import NIO
import RAW_dh25519
import RAW_base64

public typealias Key = RAW_dh25519.PublicKey

public final class WireguardInterface {
	public func run() async throws {
//        let channel = try await self.connectedChannel.get()
//        try await gracefulShutdown()
//        try? await channel.close()
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

		// Create Channel
		let bootstrap =  DatagramBootstrap(group: group)
			.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
			.channelInitializer { channel in
				channel.pipeline.addHandlers([
				PacketHandler(logLevel:.trace),
					HandshakeHandler(privateKey:self.staticPrivateKey, logLevel:.trace),
			])
		}

		// Start Channel
		let channel = try bootstrap.bind(host:"0.0.0.0", port:36361).wait()
		
		print("Server started successfully on \(channel.localAddress?.description ?? "unknown address")")
		
		let peerPublicKeyBase64 = String(RAW_base64.encode(peerPublicKey))
		var privKeyCopy = staticPrivateKey
		let myPublicKeyBase64 = String(RAW_base64.encode(PublicKey(&privKeyCopy)))
		
		print("Peer Public Key: \(peerPublicKeyBase64)")
		print("My Public Key: \(myPublicKeyBase64)")

		let myInvoker = HandshakeInvoker(invoke: HandshakeInitiationInvoke(endpoint:try! SocketAddress(ipAddress: ipAddress, port: port), publicKey: peerPublicKey), logLevel: .trace)
		try channel.pipeline.addHandler(myInvoker).wait()

		try channel.closeFuture.wait()

		print("Server closed.")
		
	}
	
	deinit {
		try? group.syncShutdownGracefully()
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

