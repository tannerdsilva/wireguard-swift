// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import RAW
import NIO
import RAW_dh25519
import RAW_base64
import Logging
import bedrock_future
import bedrock_fifo
import ServiceLifecycle
import bedrock_ip
import wireguard_crypto_core

extension Endpoint {
	public init(_ socketAddress:SocketAddress) throws {
		switch socketAddress {
			case .v4(_):
				self = .v4(V4(address:AddressV4(socketAddress.ipAddress!)!, port:Port(RAW_native:UInt16(socketAddress.port!))))
			case .v6(_):
				self = .v6(V6(address:AddressV6(socketAddress.ipAddress!)!, port:Port(RAW_native:UInt16(socketAddress.port!))))
			default:
				throw POSIXError(.ENOTSUP)
		}
	}
}

/// Represents a peer on the WireGuard interface. Each peer has a unique public key assosiated with it.
public struct Peer:Sendable {
	public let publicKey:PublicKey
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
public final actor WGInterface<TransactableDataType>:Sendable, Service where TransactableDataType:RAW_decodable, TransactableDataType:RAW_encodable, TransactableDataType:Sendable {
	public enum State {
		case initialized
		case engaged(Channel)
	}

	public struct InvalidInterfaceStateError:Swift.Error {}

	let logger:Logger

	private let bootstrappedFuture:Future<Void, Swift.Error> = Future<Void, Swift.Error>()

	/// The private key of the interface (owners private key)
	let staticPrivateKey:PrivateKey
	
	/// The initial configuration for peers upon interface creation
	let initialConfiguration:[Peer]
	
	/// Data handler channel
	let dh:DataHandler
	
	private var state:State = .initialized

	private let group:MultiThreadedEventLoopGroup

	public let inboundData = FIFO<(PublicKey, TransactableDataType), Swift.Error>()

	/// Initialize with owners `PrivateKey` and the configuration `[Peer]`
	public init(staticPrivateKey: consuming PrivateKey, initialConfiguration:[Peer] = [], logLevel:Logger.Level) throws {
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
		self.staticPrivateKey = staticPrivateKey
		self.initialConfiguration = initialConfiguration
		self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
		self.dh = DataHandler(logLevel: .trace, initialConfiguration: initialConfiguration)
	}

	public func waitForChannelInit() async throws {
		_ = await bootstrappedFuture.result()
	}
	
	/// Starts the WireGuard interface
	public func run() async throws {
		switch state {
			case .initialized:
				let hs = HandshakeHandler(privateKey:self.staticPrivateKey, logLevel:.trace)
				let dhh = DataHandoffHandler<TransactableDataType>(handoff:inboundData, channelEnabledFuture: bootstrappedFuture, logLevel:logger.logLevel)
				let bootstrap =  DatagramBootstrap(group: group)
					.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
					.channelInitializer { [hs = hs, dh = dh, dhh = dhh]channel in
						channel.pipeline.addHandlers([
							PacketHandler(logLevel:.trace),
							hs,
							dh,
							KcpHandler(logLevel: .trace),
							SplicerHandler(logLevel: .trace),
							dhh
						])
					}
				let channel = try await bootstrap.bind(host:"0.0.0.0", port:36361).get()
				state = .engaged(channel)
				logger.info("WireGuard interface started successfully on \(channel.localAddress!)")
				try await withGracefulShutdownHandler {
					try await channel.closeFuture.get()
				} onGracefulShutdown: { [c = channel, l = logger] in
					_ = c.close()
					l.debug("invoking graceful shutdown of wireguard nio interface")
				}
			case .engaged(_):
				throw InvalidInterfaceStateError()
		}

		logger.info("server closed successfully.")
	}

	public func write(publicKey: PublicKey, data:[UInt8]) async throws {
		switch state {
			case .engaged(let channel):
				let myWritePromise = channel.eventLoop.makePromise(of:Void.self)
				channel.pipeline.writeAndFlush((publicKey, data), promise:myWritePromise)
				try await myWritePromise.futureResult.get()
			default:
				throw InvalidInterfaceStateError()
		}
	}
	
	public func addPeer(_ peer: Peer) {
		dh.addPeer(peer: peer)
	}
	
	public func removePeer(_ peer: Peer) {
		dh.removePeer(peer: peer)
	}
	
}


