import Foundation
import RAW
import RAW_dh25519
import RAW_chachapoly
import RAW_base64

/// File is work in progress

@RAW_staticbuff(bytes: 8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
internal struct Result8:Sendable {}

internal struct DataMessage:Sendable {
    internal static func forgeDataMessage(receiverIndex:PeerIndex, nonce:inout Result8, transportKey: Result32, plainText:[UInt8]) throws -> DataPayload {
        // step 1: P := P || 0... Zero Padding the Packet
        let PLength:Int = plainText.count
        let zeros = [UInt8](repeating: 0, count: 16 * Int(ceil(Double(PLength)/16.0)) - PLength)
        var joined = plainText + zeros
        
        // step 2: msg.counter = nonce
        let msgCounter = nonce
        var nonceUInt64:UInt64 = nonce.RAW_native()
        
        // step 3: msg.packet := AEAD(Tm, Nm, P, e)
        var e:[UInt8] = []
        let (packet, packetTag) = try withUnsafePointer(to: transportKey) { transportKey in
            try aeadEncrypt(key: transportKey, counter: nonceUInt64, text: &joined, aad: &e)
        }
        
        // step 4: nonce := nonce + 1
        nonceUInt64 += 1
        nonce = Result8(RAW_native: nonceUInt64)
        
        return DataPayload(payload: Payload(receiverIndex: receiverIndex, counter:nonce, packetTag:packetTag), data: packet)
    }
    
    /// Need to figure out 0 byte padding descryption
    internal static func decryptDataMessage(_ message: UnsafePointer<DataMessage.DataPayload>, nonce:inout Result8, transportKey: Result32) throws -> [UInt8] {
        
        // step 2: msg.counter = nonce
        let msgCounter = nonce
        var nonceUInt64:UInt64 = nonce.RAW_native()
        
        // step 3: msg.packet := AEAD(Tm, Nm, P, e)
        var e:[UInt8] = []
        let packetData = try withUnsafePointer(to: transportKey) { transportKey in
            try aeadDecrypt(key:transportKey, counter:nonceUInt64, cipherText:message.pointer(to:\.data)!, aad:&e, tag:message.pointee.payload.packetTag)
        }
        
        // step 4: nonce := nonce + 1
        nonceUInt64 += 1
        nonce = Result8(RAW_native: nonceUInt64)
        
        return packetData
    }
    
    @RAW_staticbuff(concat:TypeHeading.self, PeerIndex.self, Result8.self, Tag.self)
    internal struct Payload:Sendable {
        /// message type (type and reserved)
        let typeHeader:TypeHeading
        /// responder's peer index (I_r)
        internal let receiverIndex:PeerIndex
        /// packet counter key
        internal let counter:Result8
        /// packet tag of message
        internal let packetTag:Tag

        /// initializes a new HandshakeResponseMessage
        fileprivate init(receiverIndex:PeerIndex, counter:Result8, packetTag:Tag) {
            self.typeHeader = 0x4
            self.receiverIndex = receiverIndex
            self.counter = counter
            self.packetTag = packetTag
        }
    }
    
    internal struct DataPayload:Sendable {
        let payload:Payload
        let data:[UInt8]
        
        fileprivate init(payload:Payload, data:[UInt8]) {
            self.payload = payload
            self.data = data
        }
    }
}
