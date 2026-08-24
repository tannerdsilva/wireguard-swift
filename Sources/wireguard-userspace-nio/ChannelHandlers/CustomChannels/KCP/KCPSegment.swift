import struct NIO.ByteBuffer
import struct NIO.ByteBufferView

/// A KCP segment packet that is encoded to and decoded from the wire.
public struct KCPSegment:Sendable, Hashable {
	/// The header of the KCP segment.
	internal var header:Header
	/// The data payload of the KCP segment (can be zero-length).
	internal let data:ByteBufferView
	/// Runtime metadata associated with a KCP segment that is not transmitted on the wire.
	internal var runtimeMetadata:RuntimeMetadata = RuntimeMetadata()

	/// The header section of the KCP segment.
	internal struct Header:Sendable, Hashable {
		/// The conversation ID that this segment belongs to.
		internal let conversationID:UInt16
		/// The command signal that this segment is carrying.
		internal var command:Command
		/// The fragment number of this segment.
		internal let fragmentID:UInt8
		/// The receive window size.
		internal var receiveWindowSize:UInt16
		/// The current timestamp of this segment, used for RTT calculations.
		internal var timestamp:UInt64
		/// The sequence number of this segment.
		internal var sequenceNumber:UInt32
		/// The earliest unacknowledged segment.
		internal var una:UInt32
		/// The length of the data carried in this segment.
		internal let dataLength:UInt16

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

		/// Decodes a KCP segment header from a byte buffer. The bytes will be read from the buffer.
		internal init?(decode buffer:inout ByteBuffer) {
			guard let cid = buffer.readInteger(endianness: .big, as:UInt16.self) else {
				return nil
			}
			conversationID = cid
			
			guard let cmdByte = buffer.readInteger(as:UInt8.self) else {
				return nil
			}
			guard let cmdEnum = Command(rawValue: cmdByte) else {
				return nil
			}
			command = cmdEnum

			guard let frgParsed = buffer.readInteger(as:UInt8.self) else {
				return nil
			}
			fragmentID = frgParsed

			guard let wndParsed = buffer.readInteger(endianness: .big, as:UInt16.self) else {
				return nil
			}
			receiveWindowSize = wndParsed

			guard let tsParsed = buffer.readInteger(endianness: .big, as:UInt64.self) else {
				return nil
			}
			timestamp = tsParsed

			guard let snParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			sequenceNumber = snParsed

			guard let unaParsed = buffer.readInteger(endianness: .big, as:UInt32.self) else {
				return nil
			}
			una = unaParsed

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
	/// KCP commands that can be sent within a segment.
	internal enum Command:UInt8, Hashable, Equatable {
		/// KCP command signifying a new connection.
		case genesis = 80
		/// KCP command signifying the push of data.
		case push = 81
		/// KCP command signifying an acknowledgement of received data.
		case ack = 82
		/// KCP command signifying a window probe request.
		case probeRequest = 83
		/// KCP command signifying a window size response.
		case probeResponse = 84
		/// KCP command signifying that the connection should terminate.
		case probeKill = 85
	}
}

extension KCPSegment {
	/// Runtime metadata associated with a KCP segment that is not transmitted on the wire.
	internal struct RuntimeMetadata:Sendable, Hashable {
		/// Resend timestamp. The time to retransmit if no ACK is received.
		internal var resendts:UInt64 = 0
		/// Retransmission timeout, computed based on the round-trip time.
		internal var rto:UInt64 = 0
		/// Fast-ack counter.
		internal var fastack:UInt32 = 0
		/// Transmit count. Incremented when this segment is sent.
		internal var xmit:UInt32 = 0
	}
}

extension KCPSegment {
	/// Decodes a KCP segment from a byte buffer. The bytes will be read from the buffer.
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

	/// Encodes the KCP segment into the byte buffer, appending the bytes to the buffer.
	public func encode(to buffer:inout ByteBuffer) {
		header.encode(to:&buffer)
		buffer.writeBytes(data)
	}
}

extension KCPSegment.Command:CustomDebugStringConvertible {
	/// A short mnemonic for the command, such as `GEN`, `PUSH`, or `ACK`.
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
