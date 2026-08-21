import Testing
import Foundation
import RAW_dh25519
import RAW_base64
import RAW
import NIO
import Logging
import wireguard_crypto_core
@testable import wireguard_userspace_nio

// MARK: - KCP primitive smoke tests
extension WireguardSwiftTests {

	@Suite("KCP Primitives Tests")
	struct KCPPrimitivesTests {

		@Test func linkedListAddRemovePopIterate() {
			var list = LinkedList<Int>()
			#expect(list.isEmpty)
			#expect(list.count == 0)

			let n1 = list.add(1)          // front
			list.addTail(3)               // back
			list.insert(2, after:n1)      // middle
			#expect(list.count == 3)

			let forward = list.map { $0.1 }
			#expect(forward == [1, 2, 3])

			let reverse = list.makeReverseIterator().map { $0.1 }
			#expect(reverse == [3, 2, 1])

			#expect(list.popFront() == 1)
			#expect(list.popBack() == 3)
			#expect(list.popFront() == 2)
			#expect(list.isEmpty)
			#expect(list.count == 0)
		}

		@Test func linkedListRemoveCurrentDuringIteration() {
			var list = LinkedList<Int>()
			for i in 0..<5 { list.addTail(i) }   // [0,1,2,3,4]

			var removed = 0
			for (node, value) in list.makeIterator() {
				if value.isMultiple(of:2) {
					list.remove(node)
					removed += 1
				}
			}
			#expect(removed == 3)
			#expect(list.count == 2)
			#expect(list.map { $0.1 } == [1, 3])
		}

		@Test func linkedListClear() {
			var list = LinkedList<Int>()
			for i in 0..<100 { list.addTail(i) }
			#expect(list.count == 100)
			list.clear()
			#expect(list.count == 0)
			#expect(list.isEmpty)
			#expect(list.front == nil)
			#expect(list.back == nil)
		}

		@Test func kcpSegmentEncodeDecodeRoundTrip() throws {
			var payloadBuffer = ByteBuffer(bytes:[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03])
			let dataView = payloadBuffer.readableBytesView
			let header = KCPSegment.Header(conv:0x1234, cmd:.push, rcv_wnd_size:256, frg:2, sn:42, ts:9000, una:7, len:UInt16(dataView.count))
			let original = KCPSegment(header:header, data:dataView)

			var encoded = ByteBuffer()
			original.encode(to:&encoded)

			var decodeBuffer = encoded
			guard let decoded = KCPSegment(decode:&decodeBuffer) else {
				Issue.record("failed to decode a valid KCPSegment")
				return
			}
			#expect(decoded.header.conversationID == original.header.conversationID)
			#expect(decoded.header.command == original.header.command)
			#expect(decoded.header.fragmentID == original.header.fragmentID)
			#expect(decoded.header.receiveWindowSize == original.header.receiveWindowSize)
			#expect(decoded.header.timestamp == original.header.timestamp)
			#expect(decoded.header.sequenceNumber == original.header.sequenceNumber)
			#expect(decoded.header.una == original.header.una)
			#expect(decoded.header.dataLength == original.header.dataLength)
			#expect(Array(decoded.data) == Array(original.data))
			// the decoder must consume exactly one segment worth of bytes
			#expect(decodeBuffer.readableBytes == 0)
		}

		@Test func kcpSegmentEmptyDataRoundTrip() throws {
			let header = KCPSegment.Header(conv:0x00FF, cmd:.ack, rcv_wnd_size:128, frg:0, sn:1, ts:5, una:0, len:0)
			let original = KCPSegment(header:header, data:ByteBufferView())

			var encoded = ByteBuffer()
			original.encode(to:&encoded)
			#expect(encoded.readableBytes == Int(IKCP_OVERHEAD))

			var decodeBuffer = encoded
			guard let decoded = KCPSegment(decode:&decodeBuffer) else {
				Issue.record("failed to decode an empty KCPSegment")
				return
			}
			#expect(decoded.header.dataLength == 0)
			#expect(decoded.data.isEmpty)
			#expect(decodeBuffer.readableBytes == 0)
		}

		@Test func kcpSegmentDecodeRejectsTruncatedData() {
			// a header claiming 4 bytes of data but only 2 present must fail to decode
			var payloadBuffer = ByteBuffer(bytes:[0x01, 0x02])
			let view = payloadBuffer.readableBytesView
			let header = KCPSegment.Header(conv:0x00, cmd:.push, rcv_wnd_size:0, frg:0, sn:0, ts:0, una:0, len:4)
			let seg = KCPSegment(header:header, data:view)

			var encoded = ByteBuffer()
			seg.encode(to:&encoded)

			var decodeBuffer = encoded
			let decoded = KCPSegment(decode:&decodeBuffer)
			#expect(decoded == nil)
		}
	}
}
