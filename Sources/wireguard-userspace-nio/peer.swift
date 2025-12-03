import NIO
import RAW
import RAW_dh25519
import RAW_base64
import bedrock_fifo
import bedrock_ip
import wireguard_crypto_core

/// Protocol that lays out the required variables of any peer information.
/// Peer Information is passed into the WireGuard interface channels through initialization and whenever the peer configuration changes.
/// Any additional peer information needed for any CustomChannels should be added onto any items conforming to this protocol.
public protocol PeerInformation:Sendable {
	var publicKey:PublicKey { get }
	var sharedKey:MemoryGuarded<SharedKey>? { get }
	var endpoint:Endpoint? { get }
	var inboundData:FIFO<ByteBuffer, Swift.Error>? { get }
}

/// Simple implementation of PeerInformation.
public struct PeerInfo:PeerInformation, Sendable {
	/// The public key of the peer.
	public let publicKey:PublicKey
	/// The shared key of the peer. Set to 0^32 when nil.
	public let sharedKey:MemoryGuarded<SharedKey>?
	/// The ip address and port of the peer.
	public let endpoint:Endpoint?
	/// The internal keep alive of the peer utilized by the keep alive custom channel.
	public let internalKeepAlive:TimeAmount?
	/// The data fifo for incoming decrypted data from this peer.
	public let inboundData:FIFO<ByteBuffer, Swift.Error>?
	
	/// Initializer for an ip address and port
	public init(publicKey: PublicKey, sharedKey: MemoryGuarded<SharedKey>? = nil, ipAddress:String?, port:Int?, internalKeepAlive: TimeAmount?, inboundData:FIFO<ByteBuffer, Swift.Error>?) {
		self.publicKey = publicKey
		self.sharedKey = sharedKey
		self.internalKeepAlive = internalKeepAlive
		self.inboundData = inboundData
		
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
	
	/// Initializer for an `Endpoint`
	public init(publicKey: PublicKey, sharedKey: MemoryGuarded<SharedKey>? = nil, endpoint:Endpoint?, internalKeepAlive: TimeAmount?, inboundData:FIFO<ByteBuffer, Swift.Error>?) {
		self.publicKey = publicKey
		self.sharedKey = sharedKey
		self.internalKeepAlive = internalKeepAlive
		self.inboundData = inboundData
		self.endpoint = endpoint
	}
}

// MARK: Codable Extensions

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

extension PeerInfo:Codable {
	enum CodingKeys: String, CodingKey {
		case publicKey
		case sharedKey
		case endpoint
		case internalKeepAlive
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		
		let endpoint  = try container.decodeIfPresent(Endpoint.self, forKey: .endpoint)
		let keepAlive = try container.decodeIfPresent(TimeAmount.self, forKey: .internalKeepAlive)
		let fifo = FIFO<ByteBuffer, Swift.Error>()

		let publicKeyString = try container.decode(String.self, forKey: .publicKey)
		let publicKeyBytes = try RAW_base64.decode(publicKeyString)
		guard publicKeyBytes.count == 32 else {
			fatalError("Public Key failed to decode.")
		}
		let publicKey = RAW_dh25519.PublicKey(RAW_staticbuff: publicKeyBytes)
		
		let sharedKeyString = try container.decodeIfPresent(String.self, forKey: .sharedKey)
		guard let sharedKeyString = sharedKeyString else {
			self.init(publicKey: publicKey,
					  sharedKey: nil,
					  endpoint:endpoint,
					  internalKeepAlive: keepAlive,
					  inboundData: fifo)
			return
		}
		let bytes = try RAW_base64.decode(sharedKeyString)
		guard bytes.count == 32 else {
			fatalError("Public Key failed to decode.")
		}
		let sharedKey = bytes.withUnsafeBufferPointer { ptr in
			return MemoryGuarded<SharedKey>.init(RAW_accessed: ptr)
		}
		self.init(publicKey: publicKey,
				  sharedKey: sharedKey,
				  endpoint:endpoint,
				  internalKeepAlive: keepAlive,
				  inboundData: fifo)
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		let publicKeyString = String(RAW_base64.encode(publicKey))
		let sharedKeyString = sharedKey == nil ? nil : String(RAW_base64.encode(sharedKey!))
		try container.encode(publicKeyString, forKey: .publicKey)
		try container.encodeIfPresent(sharedKeyString, forKey: .sharedKey)
		try container.encodeIfPresent(endpoint, forKey: .endpoint)
		try container.encodeIfPresent(internalKeepAlive, forKey: .internalKeepAlive)
	}
}
