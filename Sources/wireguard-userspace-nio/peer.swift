import NIO
import RAW
import RAW_dh25519
import RAW_base64
import bedrock_fifo
import bedrock_ip
import wireguard_crypto_core

extension Endpoint: Codable {
	enum CodingKeys: String, CodingKey { case endpoint }

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)

		let epString = try container.decode(String.self, forKey: .endpoint)
		let parts = epString.split(separator: ":", maxSplits: 1).map(String.init)
		
		self = Endpoint(Address(parts[0])!, port: Endpoint.Port(integerLiteral: Int(parts[1])!))
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		try container.encode(String(describing: self), forKey: .endpoint)
	}
}

extension PublicKey: @retroactive Decodable {}
extension PublicKey: @retroactive Encodable {}
extension RAW_dh25519.PublicKey {

	enum CodingKeys: String, CodingKey { case key }

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)

		let base64 = try container.decode(String.self, forKey: .key)
		let bytes = try RAW_base64.decode(base64)
		guard bytes.count == 32 else {
			throw DecodingError.dataCorrupted(
				DecodingError.Context(codingPath: [CodingKeys.key],
									  debugDescription: "Public key must be 32 bytes")
			)
		}
		self = RAW_dh25519.PublicKey(RAW_staticbuff: bytes)
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		try container.encode(String(describing: self), forKey: .key)
	}
}

extension TimeAmount: @retroactive Decodable {}
extension TimeAmount: @retroactive Encodable {}
extension TimeAmount {
	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(Double(self.nanoseconds) / 1_000_000_000)
	}
	public init(from decoder: Decoder) throws {
		let seconds = try decoder.singleValueContainer().decode(Double.self)
		self = .nanoseconds(Int64(seconds * 1_000_000_000))
	}
}

public struct PeerInfo:Sendable {
	public let publicKey:PublicKey
	public let endpoint:Endpoint?
	public let internalKeepAlive:TimeAmount?
	public let inboundData:FIFO<ByteBuffer, Swift.Error>
	public let inboundHandshakeSignal:FIFO<HandshakeInfo, Swift.Error>
	
	public init(publicKey: PublicKey, ipAddress:String?, port:Int?, internalKeepAlive: TimeAmount?, inboundData:FIFO<ByteBuffer, Swift.Error>, inboundHandshakeSignal:FIFO<HandshakeInfo, Swift.Error>) {
		self.publicKey = publicKey
		self.internalKeepAlive = internalKeepAlive
		self.inboundData = inboundData
		self.inboundHandshakeSignal = inboundHandshakeSignal
		
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
	
	public init(publicKey: PublicKey, endpoint:Endpoint?, internalKeepAlive: TimeAmount?, inboundData:FIFO<ByteBuffer, Swift.Error>, inboundHandshakeSignal:FIFO<HandshakeInfo, Swift.Error>) {
		self.publicKey = publicKey
		self.internalKeepAlive = internalKeepAlive
		self.inboundData = inboundData
		self.inboundHandshakeSignal = inboundHandshakeSignal
		self.endpoint = endpoint
	}
}

extension PeerInfo: Codable {
	enum CodingKeys: String, CodingKey {
		case publicKey
		case endpoint
		case internalKeepAlive
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)

		// the three codable fields
		let publicKey = try container.decode(PublicKey.self, forKey: .publicKey)
		let endpoint  = try container.decodeIfPresent(Endpoint.self, forKey: .endpoint)
		let keepAlive = try container.decodeIfPresent(TimeAmount.self, forKey: .internalKeepAlive)

		let inboundData = FIFO<ByteBuffer, Swift.Error>()
		let inboundHandshakeSignal = FIFO<HandshakeInfo, Swift.Error>()

		self.init(publicKey: publicKey,
				  endpoint:endpoint,
				  internalKeepAlive: keepAlive,
				  inboundData: inboundData,
				  inboundHandshakeSignal: inboundHandshakeSignal)
	}

	// MARK: Encoding ------------------------------------------------
	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		try container.encode(publicKey, forKey: .publicKey)
		try container.encodeIfPresent(endpoint, forKey: .endpoint)
		try container.encodeIfPresent(internalKeepAlive, forKey: .internalKeepAlive)
	}
}

public final actor PeerLogistics:Sendable {
	private let channelFifoQueue:FIFO<(PublicKey, ByteBuffer), Swift.Error>
	var info: [PublicKey: FIFO<ByteBuffer, Swift.Error>] = [:]
	
	init(_ peers:[PeerInfo], channelFifoQueue: FIFO<(PublicKey, ByteBuffer), Swift.Error>) {
		for peer in peers {
			self.info[peer.publicKey] = peer.inboundData
		}
		self.channelFifoQueue = channelFifoQueue
	}
	
	func run() async throws {
		let iterator = channelFifoQueue.makeAsyncConsumer()
		while(true) {
			if let (key, incomingData) = try await iterator.next() {
				info[key]!.yield(incomingData)
			}
		}
	}
}
