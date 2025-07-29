import NIO
import RAW_dh25519
import Logging
import RAW

/// Handles the data packet encryption and decryption
internal final class DataHandler:ChannelDuplexHandler, @unchecked Sendable {
    public typealias InboundIn = PacketType
    public typealias InboundOut = Never
    
    public typealias OutboundIn = Never
    public typealias OutboundOut = PacketType
    
    /// Nsend increments by 1 for every outbound encrypted packet
    /// Nrecv used with sliding window to check if packet is valid
    private var nonceCounters:[PeerIndex:(Nsend:Result8, Nrecv:Result8)] = [:]
    private var transmitKeys:[PeerIndex:(T1:Result32, T2:Result32)] = [:]
    
    private var slidingWindow:Result8 = Result8(RAW_staticbuff:Result8.RAW_staticbuff_zeroed())
    
    private let logger:Logger

    internal init(logLevel:Logger.Level) {
        var buildLogger = Logger(label:"\(String(describing:Self.self))")
        buildLogger.logLevel = logLevel
        self.logger = buildLogger
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        
        do {
            switch unwrapInboundIn(data) {
                /// Decrypt the payload or send initiation message if unable to decrypt
                case .transit(let endpoint, var payload):
                    // later need to add condition for the handshake lifetime timer
                    if transmitKeys[payload.payload.receiverIndex] == nil {
                        logger.debug("Initiation Invoker send down to the handshake handler")
                        context.writeAndFlush(self.wrapOutboundOut(PacketType.initiationInvoker(endpoint)), promise: nil)
                        
                        // send initiation packet
                        // and somehow await for the keys to be made before processing? or something?
                    } else {
                        // check Nrecv with the sliding window
                        logger.debug("Received transit packet, decrypting data...")
                        let decryptedPacket = try DataMessage.decryptDataMessage(&payload, transportKey: transmitKeys[payload.payload.receiverIndex]!.1)
                        logger.debug("Data successfully decrypted!")
                        // send out (public key, array of bytes)
                        // do something with the decrypted data
                    }
                
                /// Calculate transmit keys and set nonce counters to 0
                case .keyExchange(let peersIndex, let c, let isInitiator):
                    logger.debug("received key exchange packet")
                    if nonceCounters[peersIndex] == nil {
                        nonceCounters[peersIndex] = (Result8(RAW_staticbuff:Result8.RAW_staticbuff_zeroed()), Result8(RAW_staticbuff:Result8.RAW_staticbuff_zeroed()))
                    } else {
                        nonceCounters[peersIndex] = (Result8(RAW_staticbuff:Result8.RAW_staticbuff_zeroed()), Result8(RAW_staticbuff:Result8.RAW_staticbuff_zeroed()))
                    }
                    let e:[UInt8] = []
                    let arr:[Result32] = try wgKDF(key: c, data: e, type: 2)
                    if(isInitiator){
                        transmitKeys[peersIndex] = (arr[0], arr[1])
                    } else {
                        transmitKeys[peersIndex] = (arr[1], arr[0])
                    }
                    logger.debug("Transmit keys calculated: \(String(describing: transmitKeys[peersIndex])) for peer \(peersIndex)")
                        
                default:
                    return
            }
        } catch {
            logger.error("error processing data packet: \(error)")
            context.fireErrorCaught(error)
        }
        
    }
}
