import NIO
import RAW_dh25519
import Logging

/// Handles the data packet encryption and decryption
internal final class DataHandler:ChannelDuplexHandler, @unchecked Sendable {
    public typealias InboundIn = PacketType
    public typealias InboundOut = Never
    
    public typealias OutboundIn = AddressedEnvelope<ByteBuffer>
    public typealias OutboundOut = PacketType
    
    /// Nsend increments by 1 for every outbound encrypted packet
    /// Nrecv used with sliding window to check if packet is valid
    private var nonceCounters:[PeerIndex:(Nsend:Counter, Nrecv:SlidingWindow<Counter>)] = [:]
    private var transmitKeys:[PeerIndex:(Tsend:Result32, Trecv:Result32)] = [:]
    private var peers:[SocketAddress:PeerIndex] = [:]
    
    /// KeepAlive variables
    private var keepaliveTasks: [SocketAddress: RepeatedTask] = [:]
    private var lastOutbound: [SocketAddress: NIODeadline] = [:]

    /// KeepAlive interval. Default 25 seconds
    private let keepaliveInterval: TimeAmount = .seconds(25)
    
    /// Re handshake variables
    private var lastHandshake: [SocketAddress: NIODeadline] = [:]
    private var rehandshakeTasks: [SocketAddress: RepeatedTask] = [:]
    private var nextAllowedReinit: [SocketAddress: NIODeadline] = [:]
    
    /// Re handshake time intervals
    private let softRekey: TimeAmount = .seconds(120)
    private let checkEvery: TimeAmount = .seconds(5)
    private let reinitBackoff: TimeAmount = .seconds(5)
    
    private var slidingWindow = SlidingWindow<Counter>(windowSize:64)
    
    private let logger:Logger

    internal init(logLevel:Logger.Level) {
        var buildLogger = Logger(label:"\(String(describing:Self.self))")
        buildLogger.logLevel = logLevel
        self.logger = buildLogger
    }
    
    private func startKeepalive(for endpoint: SocketAddress,
                                context: ChannelHandlerContext) {
        // Avoid duplicates
        if keepaliveTasks[endpoint] != nil { return }

        guard let peer = peers[endpoint] else {
            return
        }

        let task = context.eventLoop.scheduleRepeatedTask(
            initialDelay: keepaliveInterval,
            delay: keepaliveInterval
        ) { [weak self] _ in
            guard let self = self else { return }
            // All handler state is accessed on the channel event loop
            guard self.transmitKeys[peer] != nil,
                  self.nonceCounters[peer] != nil else { return }

            // Idle check: only send if no outbound for >= interval.
            // If we've never sent, treat as idle to punch NATs.
            let now = NIODeadline.now()
            let idleEnough: Bool = {
                guard let last = self.lastOutbound[endpoint] else { return true }
                return now - last >= self.keepaliveInterval
            }()
            guard idleEnough else { return }

            do {
                // NOTE: Use your **send** key and **send** nonce.
                var nsend = self.nonceCounters[peer]!.Nsend
                let tsend = self.transmitKeys[peer]!.Tsend

                let keepalive = try DataMessage.forgeDataMessage(receiverIndex: peer, nonce: &nsend, transportKey: tsend, plainText: [])

                // Emit as a transit packet to the specific endpoint
                context.writeAndFlush(self.wrapOutboundOut(.transit(endpoint, keepalive)),promise: nil)

                // Update last outbound for this peer
                self.lastOutbound[endpoint] = now
            } catch {
                self.logger.debug("Keepalive forge/send failed for peer \(peer): \(error)")
            }
        }

        keepaliveTasks[endpoint] = task
    }
    
    private func startRehandshakeTimer(for endpoint: SocketAddress,
                                       context: ChannelHandlerContext) {
        guard rehandshakeTasks[endpoint] == nil else { return }

        guard let peer = peers[endpoint] else {
            return
        }

        let task = context.eventLoop.scheduleRepeatedTask(
            initialDelay: checkEvery,
            delay: checkEvery
        ) { [weak self] _ in
            guard let self = self else { return }
            // we only re-initiate if we have keys and an endpoint
            guard self.transmitKeys[peer] != nil,
                  self.nonceCounters[peer] != nil else { return }

            let now = NIODeadline.now()
            let last = self.lastHandshake[endpoint] ?? .uptimeNanoseconds(0)

            // If the current session is older than the soft rekey target, trigger a handshake
            guard now - last >= self.softRekey else { return }

            // Simple rate limiting to avoid storms
            if let next = self.nextAllowedReinit[endpoint], now < next { return }
            self.nextAllowedReinit[endpoint] = now + self.reinitBackoff

            // Ask the handshake machinery to initiate (your pipeline knows how to handle this PacketType)
            logger.debug("Rehandshake trigger for peer \(peer)")
            context.writeAndFlush(self.wrapOutboundOut(.initiationInvoker(endpoint)), promise: nil)
        }

        rehandshakeTasks[endpoint] = task
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        for (_, task) in keepaliveTasks { task.cancel() }
        keepaliveTasks.removeAll()
        for (_, task) in rehandshakeTasks { task.cancel() }
        rehandshakeTasks.removeAll()
        nextAllowedReinit.removeAll()
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
                        let peer = payload.payload.receiverIndex
                        logger.debug("Received transit packet, decrypting data...")
                        do {
                            let decryptedPacket = try DataMessage.decryptDataMessage(&payload, transportKey: transmitKeys[peer]!.1)
                            print("Nonce: \(payload.payload.counter)")
                            print("My Nonce: \(nonceCounters[peer]!.0)")
                            /// Make sure the packet is not a keep alive packet
                            if(!decryptedPacket.isEmpty) {
                                // do something with decrypted data
                            }
                        } catch {
                            logger.debug("Authentication tag failed verification")
                            return
                        }
                        logger.debug("Data successfully decrypted")
                        // check Nonce with the sliding window
                        // send out (public key, array of bytes)
                    }
                
                /// Calculate transmit keys and set nonce counters to 0
                case .keyExchange(let endpoint, let peersIndex, let c, let isInitiator):
                    logger.debug("received key exchange packet")
                    peers[endpoint] = peersIndex
                    nonceCounters[peersIndex] = (Nsend:0, Nrecv:SlidingWindow<Counter>(windowSize: 64))
                    let e:[UInt8] = []
                    let arr:[Result32] = try wgKDF(key: c, data: e, type: 2)
                    if(isInitiator){
                        transmitKeys[peersIndex] = (arr[0], arr[1])
                    } else {
                        transmitKeys[peersIndex] = (arr[1], arr[0])
                    }
                    logger.debug("Transmit keys calculated")
                
                    lastHandshake[endpoint] = .now()
                    startKeepalive(for: endpoint, context: context)
                    startRehandshakeTimer(for: endpoint, context: context)
                    print(peers)
                        
                default:
                    return
            }
        } catch {
            logger.error("error processing data packet: \(error)")
            context.fireErrorCaught(error)
        }
        
    }
    
    /// Handles writing inbound data into an encrypted transit packet
    func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
        let envelope = unwrapOutboundIn(data)
        let endpoint = envelope.remoteAddress
        let bytes = Array(envelope.data.readableBytesView)
        do {
            if let peer = peers[endpoint] {
                let encryptedPacket = try DataMessage.forgeDataMessage(receiverIndex: peer, nonce: &nonceCounters[peer]!.0, transportKey: transmitKeys[peer]!.1, plainText: bytes)
                context.writeAndFlush(wrapOutboundOut(PacketType.transit(endpoint, encryptedPacket)), promise: promise)
                lastOutbound[endpoint] = .now()
            } else {
                logger.debug("Initiation Invoker send down to the handshake handler")
                context.writeAndFlush(self.wrapOutboundOut(PacketType.initiationInvoker(endpoint)), promise: promise)
            }
        } catch {
            logger.debug("Unable to encrypt incoming data into a transit packet")
            context.fireErrorCaught(error)
        }
    }
}
