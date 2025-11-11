import NIO
import RAW
import RAW_dh25519
import RAW_base64
import bedrock_fifo
import bedrock_ip
import wireguard_crypto_core

extension Endpoint: Codable {

	public init(from decoder: Decoder) throws {
		let container = try decoder.singleValueContainer()
		let epString = try container.decode(String.self)

		let parts = epString.split(separator: ":", maxSplits: 1).map(String.init)
		guard parts.count == 2 else {
			fatalError("Endpoint failed to decode.")
		}
		self = Endpoint(Address(parts[0])!,
						port: Endpoint.Port(integerLiteral: Int(parts[1])!))
	}
	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(String(describing: self))
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

public protocol PeerInformation:Sendable {
	var publicKey:PublicKey { get }
	var endpoint:Endpoint? { get }
	var internalKeepAlive:TimeAmount? { get }
	associatedtype inboundQueue = FIFO<ByteBuffer, Swift.Error>
	var inboundData:inboundQueue { get }
	associatedtype inboundHandshakeQueue = FIFO<HandshakeInfo, Swift.Error>
	var inboundHandshakeSignal:inboundHandshakeQueue { get }
}

public struct PeerInfoNoFifo:PeerInformation, Sendable, Hashable {
	public let publicKey:PublicKey
	public let endpoint:Endpoint?
	public let internalKeepAlive:TimeAmount?
	public typealias inboundQueue = Never
	public typealias inboundHandshakeSignal = Never
	public var inboundData: Never {
		fatalError("Access to Never")
	}
	public var inboundHandshakeSignal: Never {
		fatalError("Access to Never")
	}
	
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
	
	public init(publicKey: PublicKey, endpoint:Endpoint?, internalKeepAlive: TimeAmount?) {
		self.publicKey = publicKey
		self.internalKeepAlive = internalKeepAlive
		self.endpoint = endpoint
	}
}

public struct PeerInfo:PeerInformation, Sendable {
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

extension PeerInfoNoFifo:Codable {
	enum CodingKeys: String, CodingKey {
		case publicKey
		case endpoint
		case internalKeepAlive
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)

		// the three codable fields
		let publicKeyString = try container.decode(String.self, forKey: .publicKey)
		let bytes = try RAW_base64.decode(publicKeyString)
		guard bytes.count == 32 else {
			fatalError("Public Key failed to decode.")
		}
		let publicKey = RAW_dh25519.PublicKey(RAW_staticbuff: bytes)
		let endpoint  = try container.decodeIfPresent(Endpoint.self, forKey: .endpoint)
		let keepAlive = try container.decodeIfPresent(TimeAmount.self, forKey: .internalKeepAlive)

		self.init(publicKey: publicKey,
				  endpoint:endpoint,
				  internalKeepAlive: keepAlive)
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		let publicKeyString = String(RAW_base64.encode(publicKey))
		try container.encode(publicKeyString, forKey: .publicKey)
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
