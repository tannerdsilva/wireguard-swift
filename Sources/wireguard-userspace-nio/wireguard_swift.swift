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

public struct HandshakeInfo:Sendable {
	public let recordedTime:NIODeadline
	public let rtt:NIODeadline
	public let publicKey:PublicKey
}

/// The core actor for running WireGuard.
/// The interface uses a Swift Nio pipeline on UDP with a specified MTU.
/// It comes typed with custom Nio ChannelHandlers (See the CustomChannels protocol for more information).
/// All interfaces come with a unique `PrivateKey` and initial configuration of `[PeerInfo]` (`PrivateKey` can be generated using `dhGenerate()` from wireguard-crypto-core).
public final actor WGInterface<C:CustomChannels>:Sendable {
	public enum State {
		case initialized
		case engaging
		case engaged(Channel)
		case disconnected
		case terminated
	}
	public struct InvalidInterfaceStateError:Swift.Error {}
	private let receiveRatio:Double = 0.25

	private let logger:Logger
	private let bootstrappedFuture:Future<Void, Swift.Error> = Future<Void, Swift.Error>()
	private let staticPrivateKey:MemoryGuarded<PrivateKey>
	private var state:State = .initialized
	private let group:MultiThreadedEventLoopGroup
	private let inboundData = FIFO<(PublicKey, ByteBuffer), Swift.Error>()
	private let listeningPort:Int
	private var recentSavedConfig:[any PeerInformation]
	private let terminationFlag = TerminationFlag()

	private let ph:PacketHandler
	private let eph:EncryptedPacketHandler
	private let wgh:WireguardHandler
	private let dhh:DataHandoffHandler
	
	private let cch:any CustomChannels

	/// Initializer for any CustomChannels. The custom channels initializer argument must also be passed into the initializer.
	public init(staticPrivateKey:MemoryGuarded<PrivateKey>, mtu:UInt16, initialConfiguration:[any PeerInformation] = [], logLevel:Logger.Level, customChannelArgs:C.ArgumentType, listeningPort:Int? = nil, encryptedPacketProcessor: any EncryptedPacketProcessor = DefaultEPP()) throws {
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
		self.staticPrivateKey = staticPrivateKey
		self.group = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
		self.listeningPort = listeningPort ?? 36361
		var mtuLims = MTULimits(bidirectional:Int(mtu))
		self.ph = PacketHandler(privateKey:staticPrivateKey, mtu:&mtuLims, logLevel:logger.logLevel)
		self.eph = EncryptedPacketHandler(epp: encryptedPacketProcessor, logLevel: logLevel)
		self.wgh = WireguardHandler(privateKey:staticPrivateKey, mtu:&mtuLims, initialPeers: initialConfiguration, logLevel:logger.logLevel)
		self.cch = C(customChannelArgs, mtuLimits: &mtuLims)
		self.dhh = DataHandoffHandler(initialPeers: initialConfiguration, logLevel:logger.logLevel)
		self.recentSavedConfig = initialConfiguration
	}
	
	/// Shortened initializer for a WGInterface<KCPChannels>.
	public init(staticPrivateKey:MemoryGuarded<PrivateKey>, mtu:UInt16, initialConfiguration:[any PeerInformation] = [], logLevel:Logger.Level, listeningPort:Int? = nil, encryptedPacketProcessor: any EncryptedPacketProcessor = DefaultEPP()) throws where C == KCPChannels{
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
		self.staticPrivateKey = staticPrivateKey
		self.group = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
		self.listeningPort = listeningPort ?? 36361
		var mtuLims = MTULimits(bidirectional:Int(mtu))
		self.ph = PacketHandler(privateKey:staticPrivateKey, mtu:&mtuLims, logLevel:logger.logLevel)
		self.eph = EncryptedPacketHandler(epp: encryptedPacketProcessor, logLevel: logLevel)
		self.wgh = WireguardHandler(privateKey:staticPrivateKey, mtu:&mtuLims, initialPeers: initialConfiguration, logLevel:logger.logLevel)
		self.cch = C((staticPrivateKey, logLevel), mtuLimits: &mtuLims)
		self.dhh = DataHandoffHandler(initialPeers: initialConfiguration, logLevel:logger.logLevel)
		self.recentSavedConfig = initialConfiguration
	}
	
	/// Shortened initializer for a WGInterface<KeepAlive>.
	/// Initial configuration must be with PeerInfo rather than any PeerInformation.
	public init(staticPrivateKey:MemoryGuarded<PrivateKey>, mtu:UInt16, initialConfiguration:[PeerInfo] = [], logLevel:Logger.Level, listeningPort:Int? = nil, encryptedPacketProcessor: any EncryptedPacketProcessor = DefaultEPP()) throws where C == KeepAlive {
		var makeLogger = Logger(label: "\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
		self.staticPrivateKey = staticPrivateKey
		self.group = MultiThreadedEventLoopGroup(numberOfThreads:System.coreCount)
		self.listeningPort = listeningPort ?? 36361
		var mtuLims = MTULimits(bidirectional:Int(mtu))
		self.ph = PacketHandler(privateKey:staticPrivateKey, mtu:&mtuLims, logLevel:logger.logLevel)
		self.eph = EncryptedPacketHandler(epp: encryptedPacketProcessor, logLevel: logLevel)
		self.wgh = WireguardHandler(privateKey:staticPrivateKey, mtu:&mtuLims, initialPeers: initialConfiguration, logLevel:logger.logLevel)
		self.cch = C((initialConfiguration, logLevel), mtuLimits: &mtuLims)
		self.dhh = DataHandoffHandler(initialPeers: initialConfiguration, logLevel:logger.logLevel)
		self.recentSavedConfig = initialConfiguration
	}
}

extension WGInterface:Service {
	public func waitForChannelInit() async throws {
		_ = try await bootstrappedFuture.result()!.get()
	}

	public enum ChannelInitializationError:Swift.Error, Sendable {
		case soReceiveBufferRetrievalFailed
		case soSendBufferSetFailed
		case soWriteBufferWaterMarkSetFailed
	}
	
	actor TerminationFlag {
		var properlyTerminated = false
		func terminate() async {
			properlyTerminated = true
		}
		func isTerminated() async -> Bool {
			properlyTerminated
		}
	}
	
	/// Called by `run()`. Reruns the service if the channel disconnected due to an internet error.
	private func _run() async throws {
		switch state {
			case .initialized, .disconnected:
				state = .engaging
				let body: [any ChannelDuplexHandler & Sendable] = cch.body.map { $0 as any ChannelDuplexHandler & Sendable}
				var customChannels:[any ChannelDuplexHandler & Sendable] = [cch.head, cch.tail]
				customChannels.insert(contentsOf: body, at: 1)
				let bootstrap = DatagramBootstrap(group: group)
					.channelOption(ChannelOptions.socketOption(.so_reuseaddr), value:1)
					.channelOption(ChannelOptions.socketOption(.so_rcvbuf), value:8<<20)
					.channelInitializer { [dhh = dhh, l = logger, customChannels = customChannels] channel in
						let channelHandlers: [any ChannelHandler & Sendable] = [self.ph, self.eph, self.wgh] + customChannels + [dhh]
						let initializationFuture = channel.eventLoop.makePromise(of:Void.self)
						channel.getOption(ChannelOptions.socketOption(.so_rcvbuf)).whenComplete { [l = l] valueResult in
							guard case .success(let result) = valueResult else {
								l.error("failed to load read buffer size.")
								initializationFuture.fail(ChannelInitializationError.soReceiveBufferRetrievalFailed)
								return
							}
							let sndBuf = ceil(Double(result) * 0.75)
							channel.setOption(ChannelOptions.socketOption(.so_sndbuf), value:ChannelOptions.Types.SocketOption.Value(Int(sndBuf))).whenComplete { setResult in
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
									channel.pipeline.addHandlers(channelHandlers).cascade(to:initializationFuture)
								}
							}
						}
						return initializationFuture.futureResult
					}
					
				let channel = try await bootstrap.bind(host:"0.0.0.0", port:self.listeningPort).get()
				do { try bootstrappedFuture.setSuccess(()) } catch let error{
					fatalError("Channel could not initialize \(error)")
				}
				state = .engaged(channel)
				logger.info("WireGuard interface started successfully on \(channel.localAddress!)")
				do {
					try await withTaskCancellationHandler {
						try await withGracefulShutdownHandler {
							try await channel.closeFuture.get()
							if await !terminationFlag.isTerminated() {
								self.state = .disconnected
							}
						} onGracefulShutdown: { [c = channel, l = logger] in
							Task {
								await self.terminationFlag.terminate()
								_ = try await c.close()
							}
							l.debug("invoking graceful shutdown of wireguard nio interface")
						}
					} onCancel: { [c = channel, l = logger] in
						Task {
							await self.terminationFlag.terminate()
							_ = try await c.close()
						}
						l.debug("invoking cancellation of wireguard nio interface")
					}
				} catch let error {
					inboundData.finish(throwing: error)
					for (_, fifo) in dhh.getHandoffFifos() {
						fifo.finish(throwing: error)
					}
					wgh.getHandshakeFifo().finish(throwing: error)
					throw error
				}
				switch state {
					case .disconnected:
						logger.error("Peer disconnected. Attempting to reconnect in \(5) seconds")
						Task {
							try? await Task.sleep(for: .seconds(5))
							guard !Task.isCancelled else { return }
							wgh.setConfiguration(recentSavedConfig)
							do { try await _run() } catch { }
						}
					default:
						inboundData.finish()
						for (_, fifo) in dhh.getHandoffFifos() {
							fifo.finish()
						}
						wgh.getHandshakeFifo().finish()
						state = .terminated
				}
			case .engaged(_), .engaging, .terminated:
				throw InvalidInterfaceStateError()
		}
	}
	
	/// Starts the WireGuard interface as a Service.
	public func run() async throws {
		try await _run()
		logger.info("server closed successfully.")
	}
	
	public func close() async throws {
		switch state {
			case .engaged(let channel):
				await terminationFlag.terminate()
				try await channel.close()
			default:
				throw InvalidInterfaceStateError()
		}
	}
	
	public func setConfiguration(peerConfig:[PeerInfo]) async throws {
		switch state {
			case .engaged(let channel):
				let configPromise = channel.eventLoop.makePromise(of:Void.self)
				channel.pipeline.fireUserInboundEventTriggered(InboundEvent.peerConfigUpdate(peerConfig, configPromise))
				recentSavedConfig = peerConfig
				try await configPromise.futureResult.get()
			default:
				throw InvalidInterfaceStateError()
		}
	}
	
	public func getHandshakeFifo() -> FIFO<HandshakeInfo, Swift.Error> {
		return wgh.getHandshakeFifo()
	}
	
	/// Returns the engaged channel. Throws if the channel isn't active.
	public func getChannel() throws -> Channel  {
		switch state {
			case .engaged(let channel):
				return channel
			default:
				throw InvalidInterfaceStateError()
		}
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
	static public func write(channel:Channel, publicKey: PublicKey, data:ByteBuffer) throws {
		let myWritePromise = channel.eventLoop.makePromise(of:Void.self)
		channel.pipeline.writeAndFlush(PeerAssociated(publicKey:publicKey, associatedValue:data), promise:myWritePromise)
		try myWritePromise.futureResult.wait()
	}
}
