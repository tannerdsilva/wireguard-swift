import struct NIO.ByteBuffer
import struct NIO.ByteBufferView

/// a kcp segment packet that will be encoded and decoded to/from the wire.
public struct KCPSegment:Sendable, Hashable {
	/// the header of the kcp segment
	internal var header:Header
	/// the data payload of the kcp segment (can be zero length)
	internal let data:ByteBufferView
	/// runtime metadata associated with a kcp segment that is not transmitted on the wire.
	internal var runtimeMetadata:RuntimeMetadata = RuntimeMetadata()

	/// the header section of the kcp segment
	internal struct Header:Sendable, Hashable {
		/// the conversation ID that this segment belongs to
		internal let conversationID:UInt16
		/// the command signal that this segment is carrying
		internal var command:Command
		/// the fragment number of this segment
		internal let fragmentID:UInt8
		/// the receive window size.
		internal var receiveWindowSize:UInt16
		/// the current timestamp of this segment. used for rtt calculations.
		internal var timestamp:UInt64
		/// the sequence number of this segment
		internal var sequenceNumber:UInt32
		/// the earliest unacknowledged segment
		internal var una:UInt32
		/// the length of the data carried in this segment
		internal let dataLength:UInt16

		// not sure which of these stored instance varaibles should be `var` vs `let`, I would like to make a conclusive decision on this when the timing is right.

		internal init(conv:UInt16, cmd:Command, rcv_wnd_size:UInt16, frg:UInt8, sn:UInt32, ts:UInt64, una unacknowledged:UInt32, len:UInt16) {
			conversationID = conv
			command = cmd
			fragmentID = frg
			receiveWindowSize = rcv_wnd_size
			timestamp = ts
			sequenceNumber = sn
			una = unacknowledged
			dataLength = len
		}

		/// decode a kcp segment header from a byte buffer. the bytes will be read from the buffer.
		internal init?(decode buffer:inout ByteBuffer) {
			// read the conversation id
			guard let cid = buffer.readInteger(endianness: .big, as:UInt16.self) else {
				return nil
			}
			conversationID = cid
			
			// read the command byte and validate it by creating the enum
			guard let cmdByte = buffer.readInteger(as:UInt8.self) else {
				return nil
			}
			guard let cmdEnum = Command(rawValue: cmdByte) else {
				return nil
			}
			command = cmdEnum

			// read the fragment id
			guard let frgParsed = buffer.readInteger(as:UInt8.self) else {
				return nil
			}
			fragmentID = frgParsed

			// read the receive window size
			guard let wndParsed = buffer.readInteger(endianness: .big, as:UInt16.self) else {
				return nil
			}
			receiveWindowSize = wndParsed

			// read the rest of the header fields
			guard let tsParsed = buffer.readInteger(endianness: .big, as:UInt64.self) else {
				return nil
			}
			timestamp = tsParsed

			// read the sequence number
			guard let snParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			sequenceNumber = snParsed

			// read the next expected sequence number
			guard let unaParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			una = unaParsed

			// read the data length
			guard let lenParsed = buffer.readInteger(endianness: .big, as:UInt16.self) else {
				return nil
			}
			dataLength = lenParsed
		}

		internal func encode(to buffer:inout ByteBuffer) {
			buffer.writeInteger(conversationID, endianness:.big, as:UInt16.self)
			buffer.writeInteger(command.rawValue, as:UInt8.self)
			buffer.writeInteger(fragmentID, as:UInt8.self)
			buffer.writeInteger(receiveWindowSize, endianness:.big, as:UInt16.self)
			buffer.writeInteger(timestamp, endianness:.big, as:UInt64.self)
			buffer.writeInteger(sequenceNumber, endianness:.big, as:UInt32.self)
			buffer.writeInteger(una, endianness:.big, as:UInt32.self)
			buffer.writeInteger(dataLength, endianness:.big, as:UInt16.self)
		}
	}
}

// MARK: Command
extension KCPSegment {
	/// kcp commands that can be sent within a segment
	internal enum Command:UInt8, Hashable, Equatable {
		/// kcp command to signify a new connection
		case genesis = 80
		/// kcp command to signify the push of data
		case push = 81
		/// kcp command to signify an acknowledgement of received data
		case ack = 82
		/// kcp command to signify a window probe request
		case probeRequest = 83
		/// kcp command to signify a window size response
		case probeResponse = 84
		/// kcp command to terminate itself
		case probeKill = 85
	}
}

extension KCPSegment {
	/// runtime metadata associated with a kcp segment that is not transmitted on the wire.
	internal struct RuntimeMetadata:Sendable, Hashable {
		/// resend timestamp. the time to retransmit if no ACK is received
		internal var resendts:UInt64 = 0
		/// retransmission timeout. computed based on the round trip time.
		internal var rto:UInt64 = 0
		/// fast ack counter.
		internal var fastack:UInt32 = 0
		/// transmit count. incremented when this segment is sent.
		internal var xmit:UInt32 = 0
	}
}

extension KCPSegment {
	/// decode a kcp segment from a byte buffer. the bytes will be read from the buffer.
	internal init?(decode buffer:inout ByteBuffer) {
		guard let h = Header(decode:&buffer) else {
			return nil
		}
		guard buffer.readableBytes >= Int(h.dataLength) else {
			return nil
		}
		defer {
			buffer.moveReaderIndex(forwardBy: Int(h.dataLength))
		}
		header = h
		data = buffer.viewBytes(at:buffer.readerIndex, length: Int(h.dataLength))!
	}

	/// encode the kcp segment to a byte buffer. the bytes will be appended to the buffer.
	public func encode(to buffer:inout ByteBuffer) {
		header.encode(to:&buffer)
		buffer.writeBytes(data)
	}
}

extension KCPSegment.Command:CustomDebugStringConvertible {
	public var debugDescription:String {
		get {
			switch self {
				case .genesis:
					return "GEN"
				case .push:
					return "PUSH"
				case .ack:
					return "ACK"
				case .probeRequest:
					return "WASK"
				case .probeResponse:
					return "WINS"
				case .probeKill:
					return "KILL"
			}
		}
	}
}
