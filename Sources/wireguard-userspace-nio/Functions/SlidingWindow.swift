import RAW

internal struct SlidingWindow<T:RAW_encoded_fixedwidthinteger> {
	internal let windowSize:T.RAW_native_type
	private var bitmap:T.RAW_native_type = 0
	private var lastSequence:T.RAW_native_type = 0
    private var firstPacket:Bool = true
	internal init(windowSize ws:T.RAW_native_type) {
		self.windowSize = ws
	}
	internal mutating func isPacketAllowed(_ counter:T.RAW_native_type) -> Bool {
		var diff:T.RAW_native_type
        if firstPacket {
            firstPacket = false
            return true
        }
		guard counter != 0 else {
			// counter 0 is always invalid unless it's the first packet after handshake
			return false
		}
		if counter > lastSequence {
			diff = counter - lastSequence
			if diff < windowSize {
				bitmap <<= diff
				bitmap |= 1
			} else {
				bitmap = 1
			}
			lastSequence = counter
			return true
		}
		diff = lastSequence - counter
		if diff >= windowSize {
			// packet is too old
			return false
		}
		if (bitmap & (1 << diff)) != 0 {
			// packet is a duplicate
			return false
		}
		// mark as seen
		bitmap |= (1 << diff)
		// packet is valid
		return true
	}
}
