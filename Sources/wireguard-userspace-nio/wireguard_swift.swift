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
				throw POSIXError(.EINVAL)
		}
	}
}

extension SocketAddress {
	public init(_ endpoint:Endpoint) {
		switch endpoint {
			case .v4(let v4ep):
				self = SocketAddress(v4ep.address.sockaddr_in(port: v4ep.port.RAW_native()))
			case .v6(let v6ep):
				self = SocketAddress(v6ep.address.sockaddr_in6(port: v6ep.port.RAW_native()))
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
public final actor WGInterface<TransactableDataType>:Sendable where TransactableDataType:RAW_decodable, TransactableDataType:RAW_encodable, TransactableDataType:Sendable {
	public enum State {
		case initialized
		case engaging
		case engaged(Channel)
		case terminated
	}
	public struct InvalidInterfaceStateError:Swift.Error {}
	private let receiveRatio:Double = 0.25

	private let logger:Logger
	private let bootstrappedFuture:Future<Void, Swift.Error> = Future<Void, Swift.Error>()
	private let staticPrivateKey:MemoryGuarded<PrivateKey>
	private var state:State = .initialized
	private let group:MultiThreadedEventLoopGroup
	public let inboundData = FIFO<(PublicKey, [UInt8]), Swift.Error>()
	private let listeningPort:Int

	private let ph:PacketHandler
	private let wgh:WireguardHandler
	private let kcpsh:KCPSegment.Handler
	private let kcpcbh:KCPControlBlock.Handler

	/// Initialize with owners `PrivateKey` and the configuration `[Peer]`
	public init(staticPrivateKey:MemoryGuarded<PrivateKey>, mtu:UInt16, initialConfiguration:[PeerInfo] = [], logLevel:Logger.Level, listeningPort:Int? = nil) throws {
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
		self.staticPrivateKey = staticPrivateKey
		self.group = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
		self.listeningPort = (listeningPort == nil) ? 36361 : listeningPort!
		var mtuStep = mtu
		self.ph = PacketHandler(privateKey:staticPrivateKey, mtu:&mtuStep, logLevel:logger.logLevel)
		self.wgh = WireguardHandler(privateKey:staticPrivateKey, mtu:&mtuStep, initialPeers: initialConfiguration, logLevel:logger.logLevel)
		self.kcpsh = KCPSegment.Handler(privateKey:staticPrivateKey, mtu:&mtuStep, logLevel:logger.logLevel)
		self.kcpcbh = KCPControlBlock.Handler(key:staticPrivateKey, mtu:&mtuStep, logLevel:logger.logLevel)
	}
}

extension WGInterface:Service where TransactableDataType == [UInt8] {
	public func waitForChannelInit() async throws {
		_ = try await bootstrappedFuture.result()!.get()
	}

	public enum ChannelInitializationError:Swift.Error, Sendable {
		case soReceiveBufferRetrievalFailed
		case soSendBufferSetFailed
		case soWriteBufferWaterMarkSetFailed
	}
	
	/// Starts the WireGuard interface
	public func run() async throws {
		switch state {
			case .initialized:
				state = .engaging
				let bootstrap = DatagramBootstrap(group: group)
					.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value:1)
					.channelOption(ChannelOptions.socketOption(.so_rcvbuf), value:8<<20)
					.channelInitializer { [wgh = wgh, dhh = DataHandoffHandler(handoff:inboundData, logLevel:logger.logLevel), l = logger] channel in
						let initializationFuture = channel.eventLoop.makePromise(of:Void.self)
						channel.getOption(ChannelOptions.socketOption(.so_rcvbuf)).whenComplete { [l = l] valueResult in
							guard case .success(let result) = valueResult else {
								l.error("failed to load read buffer size.")
								initializationFuture.fail(ChannelInitializationError.soReceiveBufferRetrievalFailed)
								return
							}
							let sndBuf = ceil(Double(result) * 0.75)
							channel.setOption(ChannelOptions.socketOption(.so_sndbuf), value:Int(sndBuf)).whenComplete { setResult in
								guard case .success(_) = setResult else {
									l.error("failed to set send buffer size.")
									initializationFuture.fail(ChannelInitializationError.soSendBufferSetFailed)
									return
								}
								l.trace("loaded send buffer size.", metadata: ["so_sndbuf":"\(Int(sndBuf))"])
								channel.setOption(ChannelOptions.writeBufferWaterMark, value:ChannelOptions.Types.WriteBufferWaterMark(low:Int(sndBuf*0.3), high:Int(sndBuf*0.75))).whenComplete { wbwmResult in
									guard case .success(_) = wbwmResult else {
										l.error("failed to set write buffer water mark.")
										initializationFuture.fail(ChannelInitializationError.soWriteBufferWaterMarkSetFailed)
										return
									}
									l.notice("channel parameters determined.", metadata: ["so_sndbuf":"\(Int(sndBuf))", "so_rcvbuf":"\(result)", "wbwm_low":"\(Int(sndBuf*0.3))", "wbwm_high":"\(Int(sndBuf*0.75))"])
									channel.pipeline.addHandlers([
										self.ph,
										wgh,
										// self.kcpsh,
										// KCPSegment.StupidHandler(),
										// self.kcpcbh,
										// SplicerHandler(logLevel:l.logLevel, spliceByteLength: 50_000),
										dhh
									]).cascade(to:initializationFuture)
								}
							}
						}
						return initializationFuture.futureResult
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
				state = .terminated
			case .engaged(_), .engaging, .terminated:
				throw InvalidInterfaceStateError()
		}

		logger.info("server closed successfully.")
	}

	public func write(publicKey: PublicKey, data:[UInt8]) async throws {
		switch state {
			case .engaged(let channel):
				let myWritePromise = channel.eventLoop.makePromise(of:Void.self)
				var bytes = channel.allocator.buffer(capacity:data.count)
				bytes.writeBytes(data)
				channel.pipeline.writeAndFlush(PeerAssociated(publicKey:publicKey, associatedValue:bytes), promise:myWritePromise)
				try await myWritePromise.futureResult.get()
			default:
				throw InvalidInterfaceStateError()
		}
	}
}

extension WGInterface:AsyncSequence {
	public struct AsyncIterator:AsyncIteratorProtocol {
		private let inboundDataOut:FIFO<(PublicKey, [UInt8]), Swift.Error>.AsyncConsumerExplicit
		
		internal init(inboundData:FIFO<(PublicKey, [UInt8]), Swift.Error>) {
			inboundDataOut = inboundData.makeAsyncConsumerExplicit()
		}
		public func next() async throws -> (PublicKey, [UInt8])? {
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
