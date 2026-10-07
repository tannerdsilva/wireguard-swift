import Testing
import Foundation
import RAW_dh25519
import RAW_base64
import RAW
import NIO
import Logging
import ServiceLifecycle
import wireguard_crypto_core
import bedrock_fifo
import bedrock_ip
@testable import wireguard_userspace_nio

/// Reproduces the "could not find matching traffic for inbound data peer index"
/// failure (WireguardDuplexHandler.swift:423) caused by receiver-side state loss:
/// a sender whose session is still live keeps encrypting to a receiver index the
/// fresh receiver has never learned. The sender's data is dropped at the
/// `MPeerIndex` seek, its KCP stream retransmits into a void, and (on current
/// code) it only self-heals after the 120s `Rekey-After-Time` send trigger —
/// long after KCP has discarded the payload.
///
/// Canary semantics: this test expects the §6.5 broken-session detection
/// (`Keepalive-Timeout + Rekey-Timeout` ≈ 15s after a data send with no
/// authenticated reply, contiguous with the passive keepalive) to recover the
/// link and deliver the payload within 45 seconds. On the current code there is
/// no such detection, so the test fails (red). It is meant to pass (green) once
/// the whitepaper-parity detection is implemented.
extension WireguardSwiftTests {
    @Suite(.serialized, .timeLimit(.minutes(3)))
    struct SessionIndexMismatchTests {
        private static let aliceStaticPrivateKey: MemoryGuarded<PrivateKey> = {
            let bytes = try! RAW_base64.decode("8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI=")
            return bytes.withUnsafeBytes { raw in
                return MemoryGuarded<PrivateKey>(RAW_decode:raw)!
            }
        }()

        private static let bobStaticPrivateKey: MemoryGuarded<PrivateKey> = {
            let bytes = try! RAW_base64.decode("SD/y8yQa/DgiYRnDI9vJEiGezNn4yLd/4yL9OLnej0A=")
            return bytes.withUnsafeBytes { raw in
                return MemoryGuarded<PrivateKey>(RAW_decode:raw)!
            }
        }()

        private static let alicePublicKey: PublicKey = {
            do {
                return try PublicKey(privateKey: aliceStaticPrivateKey)
            } catch {
                fatalError("failed to load alice public key: \(error)")
            }
        }()

        private static let bobPublicKey: PublicKey = {
            do {
                return try PublicKey(privateKey: bobStaticPrivateKey)
            } catch {
                fatalError("failed to load bob public key: \(error)")
            }
        }()

        /// Returns true if the FIFO yields nothing within `seconds`.
        /// Works because an unfinished FIFO blocks on `next()`; a finished
        /// FIFO would return nil immediately. The consumer is created with
        /// `whenTaskCancelled: .finish` so cancelAll actually unblocks it —
        /// a plain `.noAction` consumer ignores cancellation and would hang
        /// the task group at scope exit.
        fileprivate func yieldsNothingWithin(
            _ fifo: FIFO<ByteBuffer, Swift.Error>,
            seconds: Double
        ) async throws -> Bool {
            let result = try await withThrowingTaskGroup(of: ByteBuffer?.self) { group in
                group.addTask {
                    try await fifo.makeAsyncConsumer().next(whenTaskCancelled: .finish)
                }
                group.addTask {
                    try await Task.sleep(for: .seconds(seconds))
                    return nil
                }
                let first = try await group.next()!
                group.cancelAll()
                return first
            }
            return result == nil
        }

        /// True if the FIFO receives at least one buffer within `seconds`.
        fileprivate func receivedWithin(
            _ fifo: FIFO<ByteBuffer, Swift.Error>,
            seconds: Double
        ) async throws -> Bool {
            return !(try await yieldsNothingWithin(fifo, seconds: seconds))
        }

        /// The scenario:
        ///  1. Alice ↔ Bob-1 establish a session and exchange a payload (control).
        ///  2. Bob-1 is replaced by fresh Bob-2 (same key/port, empty session
        ///     state) — the receiver state loss observed in production.
        ///  3. Alice keeps writing; her stale session's receiver index is unknown
        ///     to Bob-2. Every packet is dropped before decryption while Alice's
        ///     KCP retransmits into the void.
        ///  4. CANARY: on whitepaper §6.5 behavior the link self-heals ~15s after
        ///     the deaf data send (keepalive-timeout + rekey-timeout) and the
        ///     continued writes reach Bob-2. Assert delivery within 45s.
        @Test func senderLiveSessionStrandedByReceiverStateLoss() async throws {
            let logger = Logger(label: "session-index-mismatch-test")
            var cliLogger = Logger(label: "session-index-mismatch-test")
            cliLogger.logLevel = .info

            let alicePort = 37022
            let bobPort = 37021

            let aliceInbound = FIFO<ByteBuffer, Swift.Error>()
            let bobInbound1 = FIFO<ByteBuffer, Swift.Error>()
            let bobInbound2 = FIFO<ByteBuffer, Swift.Error>()

            let alicePeers = [PeerInfo(
                publicKey: Self.bobPublicKey,
                ipAddress: "127.0.0.1",
                port: bobPort,
                internalKeepAlive: nil,
                inboundData: aliceInbound
            )]
            let bobPeers = [PeerInfo(
                publicKey: Self.alicePublicKey,
                ipAddress: "127.0.0.1",
                port: alicePort,
                internalKeepAlive: nil,
                inboundData: bobInbound1
            )]

            let alice = try WGInterface<KCPChannels>(
                staticPrivateKey: Self.aliceStaticPrivateKey,
                mtu: 1400,
                initialConfiguration: alicePeers,
                logLevel: .debug,
                listeningPort: alicePort,
                encryptedPacketProcessor: DefaultEPP()
            )
            let bob1 = try WGInterface<KCPChannels>(
                staticPrivateKey: Self.bobStaticPrivateKey,
                mtu: 1400,
                initialConfiguration: bobPeers,
                logLevel: .debug,
                listeningPort: bobPort,
                encryptedPacketProcessor: DefaultEPP()
            )

            let payload1: [UInt8] = Array("payload-1".utf8)
            let payload2: [UInt8] = Array("payload-2".utf8)

            try await withThrowingTaskGroup(of: Void.self) { foo in
                foo.addTask {
                    try await alice.run()
                }
                foo.addTask {
                    try await bob1.run()
                }
                try await alice.waitForChannelInit()
                try await bob1.waitForChannelInit()

                // 1. Healthy path: handshake completes, payload 1 is delivered.
                try await alice.write(publicKey: Self.bobPublicKey, data: payload1)
                let deliveredHealthy = try await receivedWithin(bobInbound1, seconds: 6)
                #expect(deliveredHealthy, "precondition failed: payload 1 should arrive while both sides are healthy")

                // 2. Receiver state loss: Bob's interface is torn down and a
                //    fresh one (same key, same port, empty session state) takes
                //    its place — the relay-restart/KCP-reset scenario.
                try await bob1.close()
                try await Task.sleep(for: .milliseconds(300))

                let bob2 = try WGInterface<KCPChannels>(
                    staticPrivateKey: Self.bobStaticPrivateKey,
                    mtu: 1400,
                    initialConfiguration: [PeerInfo(
                        publicKey: Self.alicePublicKey,
                        ipAddress: "127.0.0.1",
                        port: alicePort,
                        internalKeepAlive: nil,
                        inboundData: bobInbound2
                    )],
                    logLevel: .debug,
                    listeningPort: bobPort,
                    encryptedPacketProcessor: DefaultEPP()
                )

                foo.addTask {
                    try await bob2.run()
                }
                try await bob2.waitForChannelInit()

                // 3. Sender keeps writing with its live (stale) session. Every
                //    packet hits Bob-2's empty MPeerIndex table and is dropped
                //    with "could not find matching traffic...".
                let keepWriting = Task {
                    for i in 0..<30 {
                        try await Task.sleep(for: .milliseconds(1000))
                        try? await alice.write(publicKey: Self.bobPublicKey, data: payload2)
                    }
                }

                // 4. CANARY: §6.5 broken-session detection (~15s) + passive
                //    keepalive should bring the link back; the continued writes
                //    must then be delivered to Bob-2. 45s window covers the
                //    15s detection, the handshake, and KCP stream recovery.
                let selfHealed = try await receivedWithin(bobInbound2, seconds: 45)
                keepWriting.cancel()
                #expect(
                    selfHealed,
                    "CANARY FAILED: receiver state loss strands the sender's live session; no §6.5 self-heal within 45s"
                )

                foo.cancelAll()
                try await foo.waitForAll()
            }
        }
    }
}
