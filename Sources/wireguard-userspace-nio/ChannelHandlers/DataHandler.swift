import NIO
import RAW_dh25519
import Logging
import bedrock_fifo

internal struct peerInfo {
    let publicKey:PublicKey
    let allowedIPs:[String]
    let endpoint:SocketAddress?
    let internalKeepAlive:TimeAmount?
}

internal enum InterfaceInstruction {
    /// Add peer to pipeline configuration
    case addPeer(peerInfo)
    /// Remove peer from pipeline configuration
    case removePeer(peerInfo)
}

/// Handles the data packet encryption and decryption
internal final class DataHandler:ChannelDuplexHandler, @unchecked Sendable {
    public typealias InboundIn = PacketType
    public typealias InboundOut = Never
    
    public typealias OutboundIn = InterfaceInstruction
    public typealias OutboundOut = PacketType
    
    /// Nsend increments by 1 for every outbound encrypted packet
    /// Nrecv used with sliding window to check if packet is valid
    private var nonceCounters:[PeerIndex:(Nsend:Counter, Nrecv:SlidingWindow<Counter>)] = [:]
    private var transmitKeys:[PeerIndex:(Tsend:Result32, Trecv:Result32)] = [:]
    
    /// Wireguard peer configuration of peer `public key` to `(allowed IPs, Internet Endpoint)`
    private var configuration:[PublicKey:(allowedIPs: Set<String>, endpoint: SocketAddress?)] = [:]
    private var IPtoKey: [String:PublicKey] = [:]
    
    /// Active wireguard sessions
    private var sessions:[PublicKey:PeerIndex] = [:] // PublicKey: (PeerIndex, PeerIndex, PeerIndex)
    private var sessionsInv:[PeerIndex: PublicKey] = [:]
    
    
    /// Pending incoming and outgoing packets
    private var pendingWriteFutures: [PublicKey: [(data:[UInt8], promise:EventLoopPromise<Void>)]] = [:]
    private let pendingOutgoingPackets: FIFO<(PublicKey,[UInt8]), Swift.Error> = .init()
    
    /// KeepAlive variables
    private var keepaliveTasks: [PeerIndex: RepeatedTask] = [:] 
    private var lastOutbound: [PeerIndex: NIODeadline] = [:]

    /// KeepAlive interval. Default 25 seconds
    private var keepaliveInterval:[PublicKey:TimeAmount] = [:]
    
    /// Re handshake variables
    private var lastHandshake: [PeerIndex: NIODeadline] = [:]
    private var rehandshakeTasks: [PeerIndex: RepeatedTask] = [:]
    private var nextAllowedReinit: [PeerIndex: NIODeadline] = [:]
    
    /// Re handshake time intervals
    private let softRekey: TimeAmount = .seconds(120)
    private let checkEvery: TimeAmount = .seconds(5)
    private let reinitBackoff: TimeAmount = .seconds(5)
    
    private let logger:Logger

    internal init(logLevel:Logger.Level, initialConfiguration: [peerInfo]? = nil) {
        var buildLogger = Logger(label:"\(String(describing:Self.self))")
        buildLogger.logLevel = logLevel
        self.logger = buildLogger
        
        if(initialConfiguration != nil) {
            for peer in initialConfiguration! {
                addPeer(peer: peer)
            }
        }
    }
    
    private func startKeepalive(for endpoint: PeerIndex, context: ChannelHandlerContext, peerPublicKey: PublicKey) {
        // Avoid duplicates
        if keepaliveTasks[endpoint] != nil { return }

        guard let peer = sessions[peerPublicKey] else {
            return
        }

        let task = context.eventLoop.scheduleRepeatedTask(
            initialDelay: keepaliveInterval[peerPublicKey]!,
            delay: keepaliveInterval[peerPublicKey]!
        ) { [weak self] _ in
            guard let self = self else { return }
            // All handler state is accessed on the channel event loop
            guard self.transmitKeys[peer] != nil,
                  self.nonceCounters[peer] != nil else { return }

            // Idle check: only send if no outbound for >= interval.
            let now = NIODeadline.now()
            let idleEnough: Bool = {
                guard let last = self.lastOutbound[endpoint] else { return true }
                return now - last >= keepaliveInterval[peerPublicKey]!
            }()
            guard idleEnough else { return }

            do {
                var nsend = self.nonceCounters[peer]!.Nsend
                let tsend = self.transmitKeys[peer]!.Tsend

                let keepalive = try DataMessage.forgeDataMessage(receiverIndex: peer, nonce: &nsend, transportKey: tsend, plainText: [])

                // Emit as a transit packet to the specific endpoint
                guard let ep = configuration[peerPublicKey]!.endpoint else {
                    return
                }
                context.writeAndFlush(self.wrapOutboundOut(.encryptedTransit(configuration[peerPublicKey]!.endpoint!, keepalive)),promise: nil)

                // Update last outbound for this peer
                self.lastOutbound[endpoint] = now
            } catch {
                self.logger.debug("Keepalive forge/send failed for peer \(peer): \(error)")
            }
        }

        keepaliveTasks[endpoint] = task
    }
    
    private func stopKeepalive(for endpoint: PeerIndex) {
        if let task = keepaliveTasks.removeValue(forKey: endpoint) {
            task.cancel()
            logger.debug("Stopped keepalive task for peer \(endpoint)")
        }
    }
    
    private func startRehandshakeTimer(for endpoint: PeerIndex, context: ChannelHandlerContext, peerPublicKey: PublicKey) {
        guard rehandshakeTasks[endpoint] == nil else { return }

        guard let peer = sessions[peerPublicKey] else {
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

            guard let ep = configuration[peerPublicKey]!.endpoint else {
                return
            }
            logger.debug("Rehandshake trigger for peer \(peer)")
            context.writeAndFlush(self.wrapOutboundOut(.initiationInvoker(peerPublicKey, configuration[peerPublicKey]!.endpoint!)), promise: nil)
        }

        rehandshakeTasks[endpoint] = task
    }
    
    private func stopRehandshake(for endpoint: PeerIndex) {
        if let task = rehandshakeTasks.removeValue(forKey: endpoint) {
            task.cancel()
            logger.debug("Stopped rehandshake task for peer \(endpoint)")
        }
        nextAllowedReinit.removeValue(forKey: endpoint)
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        for (_, task) in keepaliveTasks { task.cancel() }
        keepaliveTasks.removeAll()
        for (_, task) in rehandshakeTasks { task.cancel() }
        rehandshakeTasks.removeAll()
        nextAllowedReinit.removeAll()
    }
    
    private func decryptPacket(peerPublicKey: PublicKey, packet:consuming DataMessage.DataPayload, transportKey: Result32) -> [UInt8]? {
        /// Check validity of the nonce
        if(nonceCounters[packet.payload.receiverIndex]!.Nrecv.isPacketAllowed(packet.payload.counter.RAW_native())){
            /// Authenticate (decrypt) packet
            do {
                let decryptedPacket = try DataMessage.decryptDataMessage(&packet, transportKey: transportKey)
                
                return decryptedPacket
            } catch {
                logger.debug("Authentication tag failed verification")
                return nil
            }
        } else {
            logger.debug("Packet with nonce not allowed")
            return nil
        }
    }
    
    private func addPeer(peer: peerInfo) {
        /// Remove all matches from every peer's Allowed IPs
        let newIPs = Set(peer.allowedIPs)
        guard !newIPs.isEmpty else { return }

        for peer in configuration.keys {
            configuration[peer]?.allowedIPs.subtract(newIPs)
        }
        
        /// Add peers allowed IP addresses
        configuration[peer.publicKey, default: (allowedIPs: [], endpoint: nil)].allowedIPs.formUnion(newIPs)
        for ip in newIPs { IPtoKey[ip] = peer.publicKey }
        
        /// Add endpoint
        configuration[peer.publicKey]?.endpoint = peer.endpoint
        
        print(peer.publicKey)
        /// Add keep alive time
        if(peer.internalKeepAlive != nil){
            keepaliveInterval[peer.publicKey] = peer.internalKeepAlive
        } else {
            keepaliveInterval[peer.publicKey] = .seconds(25)
        }
    }
    
    private func removePeer(peer: peerInfo) {
        guard let peerIPs = configuration[peer.publicKey]?.allowedIPs else {
            configuration[peer.publicKey] = nil
            keepaliveInterval[peer.publicKey] = nil
            return
        }
        for ip in peerIPs { IPtoKey[ip] = nil }
        configuration[peer.publicKey] = nil
        keepaliveInterval[peer.publicKey] = nil
    }
    
    private func killSession(peerPublicKey: PublicKey) {
        guard let peerIndex = sessions.removeValue(forKey: peerPublicKey) else { return }
        
        configuration[peerPublicKey]!.endpoint = nil
        sessionsInv.removeValue(forKey: peerIndex)
        nonceCounters.removeValue(forKey: peerIndex)
        transmitKeys.removeValue(forKey: peerIndex)
        lastOutbound.removeValue(forKey: peerIndex)
        lastHandshake.removeValue(forKey: peerIndex)
        
        stopKeepalive(for: peerIndex)
        stopRehandshake(for: peerIndex)
        
        logger.debug("Killed session for \(peerIndex)")
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        do {
            switch unwrapInboundIn(data) {
                /// Decrypt the payload or send initiation message if unable to decrypt
                case .encryptedTransit(let endpoint, let payload):
                    let peerIndex = payload.payload.receiverIndex
                    /// Find assosiated peer session, else drop packet
                    guard let publicKey = sessionsInv[peerIndex] else {
                        logger.debug("Received Packet from unknown source")
                        return
                    }
                    /// Authenticate packet, else drop packet
                    guard let decryptedPacket = decryptPacket(peerPublicKey: publicKey, packet: payload, transportKey: transmitKeys[peerIndex]!.Trecv) else {
                        return
                    }
                    /// Update endpoint and kill sessions at that endpoint to prevent roaming
                    configuration[publicKey]!.endpoint = endpoint
                    for (key, value) in configuration {
                        if value.endpoint == endpoint {
                            killSession(peerPublicKey: key)
                        }
                    }
                    
                    /// Make sure the packet is not a keep alive packet
                    if(decryptedPacket.isEmpty) {
                        logger.debug("Received keep alive from \(String(describing: endpoint))")
                        return
                    }
                    
                    /// Check that plaintext is an IP packet
                    guard let ip = parseIPPacket(decryptedPacket) else {
                        return
                    }
                    
                    let srcIP = switch ip {
                        case .ipv4(let src, _, _, _, _):
                            src
                        case .ipv6(let src, _, _, _):
                            src
                    }
                    
                    /// Check if srcIP is in the routing table, else drop packet
                    guard let _ = IPtoKey[srcIP] else {
                        return
                    }
                    
                    /// Add plaintext packet to queue
                    pendingOutgoingPackets.yield((publicKey, decryptedPacket))
                    logger.debug("Decrypted plaintext packet added to queue")
                
                case .decryptedTransit(let bytes, let ip):
                    let dstIP = switch ip {
                        case .ipv4(_, let dst, _, _, _):
                            dst
                        case .ipv6(_, let dst, _, _):
                            dst
                    }
                    
                    /// Check for allowed IPs, else drop packet and send
                    /// Inform user by a standard ICMP "no route to host" packet. Return -ENOKEY to user space
                    guard let publicKey = IPtoKey[dstIP] else {
                        return
                    }
                    /// Check for available endpoint, else drop packet and send
                    /// Inform user by ICMP message. Return -EHOSTUNRECH to user space
                    guard let endpoint = configuration[publicKey]?.endpoint else {
                        return
                    }
                    /// Encrypt packet and send it out to peer
                    do {
                        if let peerIndex = sessions[publicKey] {
                            let encryptedPacket = try DataMessage.forgeDataMessage(receiverIndex: peerIndex, nonce: &nonceCounters[peerIndex]!.Nsend, transportKey: transmitKeys[peerIndex]!.Trecv, plainText: bytes)
                            context.writeAndFlush(wrapOutboundOut(PacketType.encryptedTransit(endpoint, encryptedPacket)), promise: nil)
                            lastOutbound[peerIndex] = .now()
                        } else {
                            /// Send handshake since there is no active session
                            logger.debug("Initiation Invoker send down to the handshake handler")
                            context.writeAndFlush(self.wrapOutboundOut(PacketType.initiationInvoker(publicKey, endpoint)), promise: nil)
                            
                            /// Add packet to be encrypted after handshake
                            let promise = context.eventLoop.makePromise(of: Void.self)
                            pendingWriteFutures[publicKey, default: []].append((bytes, promise))
                        }
                    } catch {
                        logger.debug("Unable to encrypt incoming data into a transit packet")
                        context.fireErrorCaught(error)
                    }
                
                /// Calculate transmit keys and set nonce counters to 0
                case .keyExchange(let peerPublicKey, let endpoint, let peerIndex, let c, let isInitiator):
                    logger.debug("received key exchange packet")
                    
                    /// Store session information
                    sessions[peerPublicKey] = peerIndex
                    sessionsInv[peerIndex] = peerPublicKey
                    
                    /// Initialize nonce counters
                    nonceCounters[peerIndex] = (Nsend:0, Nrecv:SlidingWindow<Counter>(windowSize: 64))
                    
                    /// Calculate transmit keys
                    let e:[UInt8] = []
                    let arr:[Result32] = try wgKDF(key: c, data: e, type: 2)
                    if(isInitiator){
                        transmitKeys[peerIndex] = (arr[0], arr[1])
                    } else {
                        transmitKeys[peerIndex] = (arr[1], arr[0])
                    }
                    logger.debug("Transmit keys calculated")
                
                    /// Start session timers (keep alive, re-handshake timer, ...)
                    lastHandshake[peerIndex] = .now()
                    startKeepalive(for: peerIndex, context: context, peerPublicKey: peerPublicKey)
                    startRehandshakeTimer(for: peerIndex, context: context, peerPublicKey: peerPublicKey)
                    
                    /// Handle encrypting packets waiting on handshake completion
                    guard let packets = pendingWriteFutures[peerPublicKey] else {
                        return
                    }
                    for packet in packets {
                        if let peer = sessions[peerPublicKey] {
                            let encryptedPacket = try DataMessage.forgeDataMessage(receiverIndex: peer, nonce: &nonceCounters[peer]!.Nsend, transportKey: transmitKeys[peer]!.Trecv, plainText: packet.data)
                            context.writeAndFlush(wrapOutboundOut(PacketType.encryptedTransit(endpoint, encryptedPacket)), promise: packet.promise)
                            lastOutbound[peerIndex] = .now()
                        }
                    }
                    pendingWriteFutures[peerPublicKey] = nil
                
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
        switch unwrapOutboundIn(data) {
            case .addPeer(let peer):
                addPeer(peer: peer)
            case .removePeer(let peer):
                removePeer(peer: peer)
        }
    }
}
