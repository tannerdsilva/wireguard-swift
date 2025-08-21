import struct Foundation.POSIXError
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

extension SocketAddress {
	public init(_ endpoint:Endpoint) {
		switch endpoint {
			case .v4(let v4ep):
				self = SocketAddress(bedrock_ip.sockaddr_in(v4ep.address, port: v4ep.port.RAW_native()))
			case .v6(let v6ep):
				self = SocketAddress(bedrock_ip.sockaddr_in6(v6ep.address, port:v6ep.port.RAW_native()))
		}
	}
}

@available(*, deprecated, renamed:"PeerInfo")
public typealias Peer = PeerInfo

public struct PeerInfo:Sendable {
	public let publicKey:PublicKey
	public let endpoint:Endpoint?
	public let internalKeepAlive:TimeAmount?
	
	public init(publicKey: PublicKey, ipAddress:String?, port:Int?, internalKeepAlive: TimeAmount?) {
		self.publicKey = publicKey
		self.internalKeepAlive = internalKeepAlive
		
		if (ipAddress != nil && port != nil) {
			do {
				self.endpoint = try Endpoint(SocketAddress(ipAddress: ipAddress!, port: port!))
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
		case engaging
		case engaged(Channel)
	}
	public struct InvalidInterfaceStateError:Swift.Error {}

	private let logger:Logger
	private let bootstrappedFuture:Future<Void, Swift.Error> = Future<Void, Swift.Error>()
	private let staticPrivateKey:MemoryGuarded<PrivateKey>
	private let dh:DataHandler
	private var state:State = .initialized
	private let group:MultiThreadedEventLoopGroup
	public let inboundData = FIFO<(PublicKey, TransactableDataType), Swift.Error>()
	private let listeningPort:Int

	/// Initialize with owners `PrivateKey` and the configuration `[Peer]`
	public init(staticPrivateKey:MemoryGuarded<PrivateKey>, initialConfiguration:[Peer] = [], logLevel:Logger.Level, listeningPort:Int? = nil) throws {
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
		self.staticPrivateKey = staticPrivateKey
		self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
		self.dh = DataHandler(logLevel:.trace, initialConfiguration: initialConfiguration)
		self.listeningPort = (listeningPort == nil) ? 36361 : listeningPort!
	}

	public func waitForChannelInit() async throws {
		_ = try await bootstrappedFuture.result()!.get()
	}
	
	/// Starts the WireGuard interface
	public func run() async throws {
		switch state {
			case .initialized:
				state = .engaging
				let hs = HandshakeHandler(privateKey:staticPrivateKey, logLevel:.trace)
				let dhh = DataHandoffHandler<TransactableDataType>(handoff:inboundData, logLevel:logger.logLevel)
				let bootstrap =  DatagramBootstrap(group: group)
					.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value:1)
					.channelInitializer { [hs = hs, dh = dh, dhh = dhh] channel in
						channel.pipeline.addHandlers([
							PacketHandler(logLevel:.trace),
							hs,
							dh,
							KcpHandler(logLevel: .info),
							SplicerHandler(logLevel: .trace, spliceByteLength: 300_000),
							dhh
						])
					}
				let channel = try await bootstrap.bind(host:"0.0.0.0", port:self.listeningPort).get()
				try bootstrappedFuture.setSuccess(())
				state = .engaged(channel)
				logger.info("WireGuard interface started successfully on \(channel.localAddress!)")
				do {
					try await withTaskCancellationHandler {
						try await withGracefulShutdownHandler {
							try await channel.closeFuture.get()
						} onGracefulShutdown: { [c = channel, l = logger] in
							_ = c.close()
							l.debug("invoking graceful shutdown of wireguard nio interface")
						}
					} onCancel: { [c = channel, l = logger] in
						_ = c.close()
						l.debug("invoking cancellation of wireguard nio interface")
					}
				} catch let error {
					inboundData.finish(throwing: error)
					throw error
				}
				inboundData.finish()

			case .engaged(_):
				fallthrough
			case .engaging:
				throw InvalidInterfaceStateError()
		}

		logger.info("server closed successfully.")
	}

	public func asyncWrite(publicKey: PublicKey, data:[UInt8]) async throws {
		switch state {
			case .engaged(let channel):
				let myWritePromise = channel.eventLoop.makePromise(of:Void.self)
				channel.pipeline.writeAndFlush((publicKey, data), promise:myWritePromise)
				try await myWritePromise.futureResult.get()
			default:
				throw InvalidInterfaceStateError()
		}
	}
	
	public func write(publicKey: PublicKey, data:[UInt8]) throws {
		switch state {
			case .engaged(let channel):
				channel.pipeline.writeAndFlush((publicKey, data), promise:nil)
			default:
				throw InvalidInterfaceStateError()
		}
	}
}


extension WGInterface:AsyncSequence {
	public struct AsyncIterator:AsyncIteratorProtocol {
		private let inboundDataOut:FIFO<(PublicKey, TransactableDataType), Swift.Error>.AsyncConsumerExplicit
		
		internal init(inboundData:FIFO<(PublicKey, TransactableDataType), Swift.Error>) {
			inboundDataOut = inboundData.makeAsyncConsumerExplicit()
		}
		
		public func next() async throws -> (PublicKey, TransactableDataType)? {
			switch await inboundDataOut.next() {
				case .element(let element):
					return element
				case .capped(let result):
					switch result {
						case .success(_):
							return nil
						case .failure(let error):
							throw error
					}
				case .wouldBlock:
					fatalError("WGInterface AsyncIterator should never return wouldBlock. this is a critical internal error. \(#fileID):\( #line) \(#function)")
			}
		}
	}
	
	nonisolated public func makeAsyncIterator() -> AsyncIterator {
		return AsyncIterator(inboundData:inboundData)
	}
}
