import NIO

extension AddressedEnvelope:LenghExpressibleExchangeType where DataType:LenghExpressibleExchangeType {
	internal var bytesOnWire:Int {
		return data.bytesOnWire
	}
}