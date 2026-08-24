import RAW
import RAW_base64

/// Namespace collecting the fixed-size byte buffer types used throughout the library.
public struct Result {}

extension Result {
	/// An 8-byte buffer.
	@RAW_staticbuff(bytes:8)
	@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
	public struct Bytes8:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		/// A base64-encoded representation of the buffer.
		public var debugDescription:String {
			return "\(String(RAW_base64.encode(self)))"
		}
	}

	/// A 16-byte buffer.
	@RAW_staticbuff(bytes:16)
	public struct Bytes16:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		/// A base64-encoded representation of the buffer.
		public var debugDescription:String {
			return "\(String(RAW_base64.encode(self)))"
		}
	}

	/// A 24-byte buffer.
	@RAW_staticbuff(bytes:24)
	public struct Bytes24:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		/// A base64-encoded representation of the buffer.
		public var debugDescription:String {
			return "\(String(RAW_base64.encode(self)))"
		}
	}

	/// A 32-byte buffer.
	@RAW_staticbuff(bytes:32)
	public struct Bytes32:Sendable, Hashable, Equatable, Comparable, CustomDebugStringConvertible {
		/// A base64-encoded representation of the buffer.
		public var debugDescription:String {
			return "\(String(RAW_base64.encode(self)))"
		}
	}
}
