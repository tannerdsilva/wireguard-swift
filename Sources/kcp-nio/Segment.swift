import RAW
import encoded_essentials

/// a kcp segment. this is the primary data structure that is encoded to and from the wire to facilitate kcp's features.
public struct Segment<SegmentDataBodyType:Sequence & Sendable>:Sendable where SegmentDataBodyType.Element == UInt8 {
	/// the kcp segment header containing all relevant information
	public let header:Header
	/// the data that the kcp segment carries (may be zero length)
	public let data:SegmentDataBodyType
}

extension Segment {
	@RAW_staticbuff(concat:BEUInt16.self, RAW_byte.self, RAW_byte.self, BEUInt16.self, BEUInt64.self, BEUInt32.self, BEUInt32.self, BEUInt16.self)
	/// the header of the kcp segment. contains conversation, length, and windowing information.
	public struct Header:Sendable, Hashable, Equatable {
		/// the conversation ID that this segment belongs to
		public let conversationID:BEUInt16
		/// the command signal that this segment is carrying
		public let command:RAW_byte
		/// the fragment number of this segment
		public let fragmentID:RAW_byte
		/// the receive window size.
		public var receiveWindowSize:BEUInt16
		/// the current timestamp of this segment. used for rtt calculations.
		public var timestamp:BEUInt64
		/// the sequence number of this segment
		public var sequenceNumber:BEUInt32
		/// the earliest unacknowledged segment
		public var una:BEUInt32
		/// the length of the data carried in this segment
		public let dataLength:BEUInt16
	}
}

// MARK: Command
extension Segment {
	/// kcp commands that can be sent within a segment
	public enum Command:RAW_byte, Sendable, Hashable, Equatable {
		/// kcp command to signify the push of data
		case push = 81
		/// kcp command to signify an acknowledgement of received data
		case ack = 82
		/// kcp command to signify a window probe request
		case probeRequest = 83
		/// kcp command to signify a window size response
		case probeResponse = 84
	}
}

extension Segment.Header {
	public init(conv:UInt16, cmd:Segment.Command, rcv_wnd_size:UInt16, frg:UInt8, sn:UInt32, ts:UInt64, una unacknowledged:UInt32, len:UInt16) {
		conversationID = BEUInt16(RAW_native:conv)
		command = cmd.rawValue
		fragmentID = RAW_byte(RAW_native:frg)
		receiveWindowSize = BEUInt16(RAW_native:rcv_wnd_size)
		timestamp = BEUInt64(RAW_native:ts)
		sequenceNumber = BEUInt32(RAW_native:sn)
		una = BEUInt32(RAW_native:unacknowledged)
		dataLength = BEUInt16(RAW_native:len)
	}
}