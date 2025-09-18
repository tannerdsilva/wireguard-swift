import struct NIO.ByteBuffer
import struct NIO.ByteBufferView

/// a kcp segment packet that will be encoded and decoded to/from the wire.
internal struct KCPSegment {
	/// the header of the kcp segment
	internal var header:Header
	/// the data payload of the kcp segment (can be zero length)
	internal var data:ByteBufferView

	/// the header section of the kcp segment
	internal struct Header {
		/// the conversation ID that this segment belongs to
		internal let conversationID:UInt32
		/// the command signal that this segment is carrying
		internal let command:Command
		/// the fragment number of this segment
		internal let fragmentID:UInt8
		/// the receive window size.
		internal let receiveWindowSize:UInt16
		/// the current timestamp of this segment. used for rtt calculations.
		internal let timestamp:UInt32
		/// the sequence number of this segment
		internal let sequenceNumberCurrent:UInt32
		/// the next sequence number expected to be received
		internal let sequenceNumberNextExpected:UInt32
		/// the length of the data carried in this segment
		internal let dataLength:UInt32
		/// resend timestamp. the time to retransmit if no ACK is received
		internal var resendts:UInt32
		/// retransmission timeout. computed based on the round trip time.
		internal var rto:UInt32
		/// fast ack counter. incremented when duplicate packets are received.
		internal var fastack:UInt32
		/// transmit count. incremented when this segment is sent.
		internal var xmit:UInt32

		// not sure which of these stored instance varaibles should be `var` vs `let`, I would like to make a conclusive decision on this when the timing is right.

		/// decode a kcp segment header from a byte buffer. the bytes will be read from the buffer.
		internal init?(decode buffer:inout ByteBuffer) {
			// read the conversation id
			guard let cid = buffer.readInteger(endianness: .big, as:UInt32.self) else {
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
			guard let tsParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			timestamp = tsParsed

			// read the sequence number
			guard let snParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			sequenceNumberCurrent = snParsed

			// read the next expected sequence number
			guard let unaParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			sequenceNumberNextExpected = unaParsed

			// read the data length
			guard let lenParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			dataLength = lenParsed

			// read the rest of the fields that are used for kcp internal processing
			guard let resendtsParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			resendts = resendtsParsed

			// read the retransmission timeout
			guard let rtoParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			rto = rtoParsed

			// read the fastack counter
			guard let fastackParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			fastack = fastackParsed

			// read the transmit count
			guard let xmitParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			xmit = xmitParsed
		}

		internal func encode(to buffer:inout ByteBuffer) {
			buffer.writeInteger(conversationID, endianness:.big, as:UInt32.self)
			buffer.writeInteger(command.rawValue, as:UInt8.self)
			buffer.writeInteger(fragmentID, as:UInt8.self)
			buffer.writeInteger(receiveWindowSize, endianness:.big, as:UInt16.self)
			buffer.writeInteger(timestamp, endianness:.big, as:UInt32.self)
			buffer.writeInteger(sequenceNumberCurrent, endianness:.big, as:UInt32.self)
			buffer.writeInteger(sequenceNumberNextExpected, endianness:.big, as:UInt32.self)
			buffer.writeInteger(dataLength, endianness:.big, as:UInt32.self)
			buffer.writeInteger(resendts, endianness:.big, as:UInt32.self)
			buffer.writeInteger(rto, endianness:.big, as:UInt32.self)
			buffer.writeInteger(fastack, endianness:.big, as:UInt32.self)
			buffer.writeInteger(xmit, endianness:.big, as:UInt32.self)
		}
	}
}

// MARK: Command
extension KCPSegment {
	/// kcp commands that can be sent within a segment
	internal enum Command:UInt8 {
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

extension KCPSegment {
	/// decode a kcp segment from a byte buffer. the bytes will be read from the buffer.
	internal init?(decode buffer:inout ByteBuffer) {
		guard let h = Header(decode:&buffer), buffer.readableBytes >= Int(h.dataLength) else {
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
				case .push:
					return "PUSH"
				case .ack:
					return "ACK"
				case .probeRequest:
					return "WASK"
				case .probeResponse:
					return "WINS"
			}
		}
	}
}