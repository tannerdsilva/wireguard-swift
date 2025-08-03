#if os(macOS)
import Darwin

extension TAI64N {
    public init() {
        // capture the current time.
        var ts = timespec()
        clock_gettime(CLOCK_REALTIME, &ts)        
        self.seconds = _uint64_be(RAW_native:4611686018427387914 + UInt64(ts.tv_sec))
        self.nano = _uint32_be(RAW_native:UInt32(ts.tv_nsec))
    }
}
#endif

import Foundation

extension Foundation.Date {
	init(ta64n: TAI64N) {
		let seconds = Int(ta64n.seconds.RAW_native()) - 4611686018427387914
		let nanoseconds = Int(ta64n.nano.RAW_native())
		self.init(timeIntervalSince1970:TimeInterval(seconds) + TimeInterval(nanoseconds) / 1_000_000_000.0)
	}
}