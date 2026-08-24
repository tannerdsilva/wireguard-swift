import RAW

/// A WireGuard peer index, used in connection handshakes and state tracking.
@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:true)
public struct PeerIndex:Sendable, Hashable, CustomDebugStringConvertible {
	/// Generates a new peer index using system secure random bytes.
	/// - Returns: A peer index derived from secure random bytes.
	/// - Throws: If generating the secure random bytes fails.
	public static func random() throws -> Self {
		return try generateSecureRandomBytes(as:Self.self)
	}
	/// A decimal representation of the index.
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

/// The reserved field following the message-type byte. Together with the type byte
/// this forms the first 4 bytes of any WireGuard packet, unconditionally.
@RAW_staticbuff(bytes:3)
public struct Reserved:Sendable, CustomDebugStringConvertible {
	/// Creates a new `Reserved` value initialized to `[0, 0, 0]`.
	public init() {
		self = Self(RAW_staticbuff:[0, 0, 0])
	}
	/// A textual representation of the reserved field.
	public var debugDescription:String {
		return "Reserved([0, 0, 0])"
	}
}

/// The first 4 bytes of any WireGuard packet, unconditionally.
@RAW_staticbuff(concat:RAW_byte.self, Reserved.self)
public struct TypeHeading:Sendable, ExpressibleByIntegerLiteral, CustomDebugStringConvertible, Equatable, Hashable {
	/// The packet type.
	public let type:RAW_byte
	/// The reserved bytes that follow the type byte.
	public let reserved:Reserved

	/// Creates a type heading from an integer literal.
	public init(integerLiteral value:Int) {
		self.type = RAW_byte(RAW_native:UInt8(value))
		self.reserved = Reserved()
	}

	/// A decimal representation of the packet type.
	public var debugDescription: String {
		return "\(type.RAW_native())"
	}
}

/// Four bytes of zeroes used as the nonce prefix in AEAD encryption/decryption.
@RAW_staticbuff(bytes:4)
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian:false)
public struct Zeros:Sendable, CustomDebugStringConvertible {
	/// Creates a new `Zeros` value initialized to 0.
	public init() {
		self.init(RAW_native:0)
	}
	/// A textual representation of the zero field.
	public var debugDescription: String {
		return "Zeros([0, 0, 0, 0])"
	}
}

/// A 64-bit, little-endian counter.
@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:false)
public struct Counter:Sendable, ExpressibleByIntegerLiteral, Equatable, Hashable, Comparable, CustomDebugStringConvertible {
	/// The integer type used by literal initialization.
	public typealias IntegerLiteralType = UInt64
	/// Creates a counter from an integer literal.
	public init(integerLiteral value:UInt64) {
		self.init(RAW_native:value)
	}
	/// Adds `rhs` to the counter and returns the result.
	public static func + (lhs:Counter, rhs:UInt64) -> Counter {
		return Counter(RAW_native:lhs.RAW_native() + rhs)
	}
	/// Adds `rhs` to the counter in place.
	public static func += (lhs:inout Counter, rhs:UInt64) {
		lhs = Counter(RAW_native:lhs.RAW_native() + rhs)
	}
	/// A decimal representation of the counter.
	public var debugDescription: String {
		return "\(RAW_native())"
	}
}

/// A nonce with four leading zero bytes followed by a counter, used in AEAD
/// encryption and decryption.
@RAW_staticbuff(concat:Zeros.self, Counter.self)
public struct CountedNonce:Sendable, ExpressibleByIntegerLiteral, Equatable, Hashable, Comparable {
	/// The integer type used by literal initialization.
	public typealias IntegerLiteralType = UInt64
	/// The zeroed region of the counted nonce.
	public let zeros:Zeros
	/// The counter region of the counted nonce.
	public let counter:Counter

	/// Creates a counted nonce from an integer literal.
	public init(integerLiteral value:UInt64) {
		self.zeros = Zeros()
		self.counter = Counter(RAW_native:value)
	}
	/// Creates a counted nonce from a raw counter value.
	public init(counter:consuming UInt64) {
		self.zeros = Zeros()
		self.counter = Counter(RAW_native:counter)
	}
	/// Creates a counted nonce from a counter value.
	public init(counter:consuming Counter) {
		self.zeros = Zeros()
		self.counter = counter
	}
	/// Adds `rhs` to the nonce's counter and returns the result.
	public static func + (lhs:CountedNonce, rhs:UInt64) -> CountedNonce {
		return CountedNonce(counter:lhs.counter.RAW_native() + rhs)
	}
	/// Adds `rhs` to the nonce's counter in place.
	public static func += (lhs:inout CountedNonce, rhs:UInt64) {
		lhs = CountedNonce(counter:lhs.counter.RAW_native() + rhs)
	}
}
