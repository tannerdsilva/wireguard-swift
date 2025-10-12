import NIO

extension ByteBuffer:LenghExpressibleExchangeType {
	internal var bytesOnWire:Int {
		return readableBytes
	}
}