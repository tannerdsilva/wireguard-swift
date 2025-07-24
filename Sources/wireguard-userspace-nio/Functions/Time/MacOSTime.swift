#if os(macOS)
import Darwin

extension TAI64N {
    public init(localTime:Bool = false) {
        // capture the current time.
        var ts = timespec()
        clock_gettime(CLOCK_REALTIME, &ts)
        let seconds = Double(ts.tv_sec) + 37 //for some reasons
        let nanoseconds = Double(ts.tv_nsec)
        
        self.seconds = _uint64_be(RAW_native:UInt64(seconds))
        self.nano = _uint32_be(RAW_native:UInt32(nanoseconds))
    }
}
#endif
