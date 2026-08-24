import NIO
import RAW
import RAW_dh25519
import RAW_base64
import bedrock_fifo
import bedrock_ip
import wireguard_crypto_core

/// Protocol that lays out the required variables of any peer information.
/// Peer information is passed into the WireGuard interface channels through
/// initialization and whenever the peer configuration changes. Any additional
/// peer information needed for any custom channels should be added onto any
/// items conforming to this protocol.
public protocol PeerInformation:Sendable {
	/// The peer's public key.
	var publicKey:PublicKey { get }
	/// The pre-shared key, or `nil` if not in use.
	var sharedKey:MemoryGuarded<SharedKey>? { get }
	/// The peer's endpoint.
	var endpoint:Endpoint? { get }
	/// The data FIFO for incoming decrypted data from this peer.
	var inboundData:FIFO<ByteBuffer, Swift.Error>? { get }
}

/// Minimal implementation of `PeerInformation`.
public struct PeerInfo:PeerInformation, Sendable {
	/// The public key of the peer.
	public let publicKey:PublicKey
	/// The shared key of the peer. Set to `nil` when not in use.
	public let sharedKey:MemoryGuarded<SharedKey>?
	/// The IP address and port of the peer.
	public let endpoint:Endpoint?
	/// The internal keep-alive of the peer, utilized by the keep-alive custom channel.
	public let internalKeepAlive:TimeAmount?
	/// The data FIFO for incoming decrypted data from this peer.
	public let inboundData:FIFO<ByteBuffer, Swift.Error>?
	
	/// Initializes a peer from an IP address and port.
	/// - Parameters:
	///   - publicKey: The peer's public key.
	///   - sharedKey: The pre-shared key, or `nil`.
	///   - ipAddress: The peer's IP address.
	///   - port: The peer's port.
	///   - internalKeepAlive: The keep-alive interval for the peer, or `nil`.
	///   - inboundData: The FIFO for inbound data from this peer.
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
	
	/// Initializes a peer from an `Endpoint`.
	/// - Parameters:
	///   - publicKey: The peer's public key.
	///   - sharedKey: The pre-shared key, or `nil`.
	///   - endpoint: The peer's endpoint.
	///   - internalKeepAlive: The keep-alive interval for the peer, or `nil`.
	///   - inboundData: The FIFO for inbound data from this peer.
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
	/// Decodes an endpoint from a single string in `address:port` form.
	/// - Throws: `DecodingError.dataCorruptedError` if the string is malformed.
	public init(from decoder: Decoder) throws {
		let container = try decoder.singleValueContainer()
		let epString = try container.decode(String.self)

		// L3: reject malformed endpoints with a decoding error rather than crashing the process.
		let parts = epString.split(separator: ":", maxSplits: 1).map(String.init)
		guard
			parts.count == 2,
			let portValue = Int(parts[1]),
			(0...Int(UInt16.max)).contains(portValue),
			let address = Address(parts[0])
		else {
			throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid endpoint: \(epString)")
		}
		self = Endpoint(address, port: Endpoint.Port(integerLiteral: portValue))
	}
	/// Encodes the endpoint as a single string in `address:port` form.
	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(String(describing: self))
	}
}


extension TimeAmount: @retroactive Decodable {}
extension TimeAmount: @retroactive Encodable {}
extension TimeAmount {
	/// Encodes the duration as a number of seconds with fractional precision.
	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(Double(self.nanoseconds) / 1_000_000_000)
	}
	/// Decodes a duration from a number of seconds with fractional precision.
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

	/// Decodes a peer from the given keyed container. The public and shared keys
	/// are stored as base64 strings.
	/// - Throws: `DecodingError.dataCorruptedError` if a key does not decode to
	/// exactly 32 bytes.
	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		
		let endpoint  = try container.decodeIfPresent(Endpoint.self, forKey: .endpoint)
		let keepAlive = try container.decodeIfPresent(TimeAmount.self, forKey: .internalKeepAlive)
		let fifo = FIFO<ByteBuffer, Swift.Error>()

		let publicKeyString = try container.decode(String.self, forKey: .publicKey)
		let publicKeyBytes = try RAW_base64.decode(publicKeyString)
		guard publicKeyBytes.count == 32 else {
			// L3: fail the decode rather than crashing the process on a malformed config.
			throw DecodingError.dataCorruptedError(forKey:.publicKey, in: container, debugDescription: "Public key must be 32 bytes.")
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
			throw DecodingError.dataCorruptedError(forKey:.sharedKey, in: container, debugDescription: "Shared key must be 32 bytes.")
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

	/// Encodes the peer into the given keyed container, storing the public and
	/// shared keys as base64 strings.
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
