#if os(macOS)
import Darwin

extension TAI64N {
	public init(local:Bool = false) {
		// capture the current time.
		var ts = timespec()
		clock_gettime(CLOCK_REALTIME, &ts)
		let seconds = ts.tv_sec
		let nanoseconds = ts.tv_nsec
		
		switch local {
			case false:
				// capture the local time and account for the timezone adjustments
				var Cnow = time_t()
				let loc = localtime(&Cnow).pointee
				var offset = Double(loc.tm_gmtoff)
				
				// correct for daylight savings time if it is in effect
				if loc.tm_isdst > 0 {
					offset += 3600
				}
				
				self.seconds = _uint64_be(RAW_native:UInt64(Int64(seconds) + Int64(offset)))
				self.nano = _uint32_be(RAW_native:UInt32(nanoseconds))
			case true:
				self.seconds = _uint64_be(RAW_native:UInt64(seconds))
				self.nano = _uint32_be(RAW_native:UInt32(nanoseconds))
		}
	}
}
#endif
