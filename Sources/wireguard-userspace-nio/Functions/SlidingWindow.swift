import struct RAW.size_t

internal struct ReplayWindow {
	internal let windowSize:size_t
	private var bitmap:UInt64 = 0
	private var lastSequence:UInt64 = 0
	internal init(windowSize ws:size_t) {
		self.windowSize = ws
	}
	internal mutating func isPacketAllowed(_ counter:UInt64) -> Bool {
		var diff:UInt64
		guard counter != 0 else {
			// counter 0 is always valid
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