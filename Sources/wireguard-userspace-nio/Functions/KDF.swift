import RAW


internal func wgKDF<K, A>(key:UnsafePointer<K>, data:borrowing A, type: Int) throws -> [Result32] where A:RAW_accessible, K:RAW_staticbuff, K.RAW_staticbuff_storetype == Key.RAW_staticbuff_storetype {
    
    let genKey:Result32 = try wgHmac(key:key, data:data) // T0 = HMAC(key,input)
    var previous:Result32 = genKey
    
    var result:[Result32] = []
    
    for i in 1...type {
        if i==1 {
            // First iteration
            // T1 = HMAC(T0, 0x1)
            let T1 = try withUnsafePointer(to: genKey) { genKey in
                try wgHmac(key:genKey, data:[UInt8](unsafeUninitializedCapacity:1) { buffer, count in
                    buffer[0] = UInt8(1)
                    count = 1
                })
            }
            
            previous = T1
            result.append(T1)
        } else {
            // nth case scenario
            // Ti = HMAC(T0, Ti-1 || 0xi)
            
            let input = [UInt8](unsafeUninitializedCapacity:MemoryLayout<Result32>.size + 1) { buffer, count in
                previous.RAW_encode(dest:buffer.baseAddress!)[0] = UInt8(i)
                count = MemoryLayout<Result32>.size + 1
            }
            
            let Ti:Result32 = try withUnsafePointer(to: genKey) { genKey in
                try wgHmac(key:genKey, data:input)
            }
            previous = Ti
            
            result.append(Ti)
        }
    }
    
    return result
}
