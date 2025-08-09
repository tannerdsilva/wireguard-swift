import RAW

/// represents a wireguard peer index. the peer index is a crucial structure in connection handshakes and state tracking.
@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
public struct PeerIndex:Sendable, Hashable, CustomDebugStringConvertible {
	/// generate a new peer index using system secure random bytes.
	/// - returns: a new peer index based on secure random bytes.
	/// - throws: if the secure random bytes generation fails.
	public static func random() throws -> Self {
		return try generateSecureRandomBytes(as:Self.self)
	}
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

/// defines the reserved field that follows the message type byte. these two items make up the first 4 bytes of any wireguard packet, unconditionally.
@RAW_staticbuff(bytes:3)
public struct Reserved:Sendable, CustomDebugStringConvertible {
	/// initializes a new Reserved
	public init() {
		self = Self(RAW_staticbuff:[0, 0, 0])
	}
	public var debugDescription:String {
		return "Reserved([0, 0, 0])"
	}
}

/// makes up the first 4 bytes of any wireguard packet, unconditionally.
@RAW_staticbuff(concat:RAW_byte.self, Reserved.self)
public struct TypeHeading:Sendable, ExpressibleByIntegerLiteral, CustomDebugStringConvertible {
	/// the type of packet
	public let type:RAW_byte
	/// reserved bytes that follow the type byte
	public let reserved:Reserved

	public init(integerLiteral value:UInt8) {
		self.type = RAW_byte(RAW_native:value)
		self.reserved = Reserved()
	}

	public var debugDescription: String {
		return "\(type.RAW_native())"
	}

	/// validates that the type is a valid wireguard packet type and that the reserved bytes are all zero.
	/// - returns: true if the type is valid and the reserved bytes are all zero, false otherwise.
	public borrowing func isValid() -> Bool {
		switch type {
			case 0x1, 0x2, 0x3, 0x4:
				return reserved.RAW_access {
					guard $0[0] == 0 && $0[1] == 0 && $0[2] == 0 else {
						return false
					}
					return true
				}
			default:
				return false
		}
	}
}

@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:false)
/// four bytes of zeroes that are used in the AEAD encryption/decryption process.
public struct Zeros:Sendable, CustomDebugStringConvertible {
	public init() {
		self.init(RAW_native:0)
	}
	public var debugDescription: String {
		return "Zeros([0, 0, 0, 0])"
	}
}

/// represents a 64bit big endian counter.
@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:false)
public struct Counter:Sendable, ExpressibleByIntegerLiteral, Equatable, Hashable, Comparable, CustomDebugStringConvertible {
	public typealias IntegerLiteralType = UInt64
	public init(integerLiteral value:UInt64) {
		self.init(RAW_native:value)
	}
	/// add a value to the counter. the right hand value must be a `UInt64` type.
	public static func + (lhs:Counter, rhs:UInt64) -> Counter {
		return Counter(RAW_native:lhs.RAW_native() + rhs)
	}
	/// add a value to the counter in place. the right hand value must be a `UInt64` type.
	public static func += (lhs:inout Counter, rhs:UInt64) {
		lhs = Counter(RAW_native:lhs.RAW_native() + rhs)
	}
	public var debugDescription: String {
		return "\(RAW_native())"
	}
}

/// represents a nonce with 4 leading zeroes followed by a counter. this is used in the AEAD encryption/decryption process.
@RAW_staticbuff(concat:Zeros.self, Counter.self)
public struct CountedNonce:Sendable, ExpressibleByIntegerLiteral, Equatable, Hashable, Comparable {
    public init(integerLiteral value:UInt64) {
        self.zeros = Zeros()
        self.counter = Counter(RAW_native:value)
    }
	/// this type expresses (literally) as a 64bit unsigned integer
    public typealias IntegerLiteralType = UInt64
	/// the zeroed region of the counted nonce
	public let zeros:Zeros
	/// the counter region of the counted nonce
	public let counter:Counter
	public init(counter:consuming UInt64) {
		self.zeros = Zeros()
		self.counter = Counter(RAW_native:counter)
	}
	public init(counter:consuming Counter) {
		self.zeros = Zeros()
		self.counter = counter
	}
	public static func + (lhs:CountedNonce, rhs:UInt64) -> CountedNonce {
		return CountedNonce(counter:lhs.counter.RAW_native() + rhs)
	}
	public static func += (lhs:inout CountedNonce, rhs:UInt64) {
		lhs = CountedNonce(counter:lhs.counter.RAW_native() + rhs)
	}
}