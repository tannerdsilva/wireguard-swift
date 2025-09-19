import NIO
import RAW
import RAW_dh25519
import kcp_swift
import Logging
import wireguard_crypto_core

internal final class KcpHandlerV2:ChannelDuplexHandler, @unchecked Sendable {
	internal typealias InboundIn = (PublicKey, ByteBuffer)
	internal typealias InboundOut = (PublicKey, [UInt8])
	
	internal typealias OutboundIn = (PublicKey, [UInt8])
	internal typealias OutboundOut = (PublicKey, ByteBuffer)
	
	private var kcp:[PublicKey:[KCPControlBlock]] = [:]
			
	private var pendingOutgoing:[PublicKey:[(data: [UInt8], promise: EventLoopPromise<Void>?)]] = [:]
	private var pendingIncoming:[PublicKey:[[UInt8]]] = [:]
	
    private let ourKey:PublicKey
	private let logger:Logger
		
	internal init(key:PublicKey, logLevel:Logger.Level) {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = logLevel
		logger = buildLogger

        ourKey = key
	}

	internal func handlerAdded(context:ChannelHandlerContext) {
		logger.trace("handler added to NIO pipeline.")
	}
	
	internal func handlerRemoved(context:ChannelHandlerContext) {
		logger.trace("handler removed from NIO pipeline.")
	}	
	
	// Receiving kcp segment
	internal func channelRead(context:ChannelHandlerContext, data:NIOAny) {
		let (key, data) = unwrapInboundIn(data)

        // let bytes: [UInt8] = data.getBytes(at: data.readerIndex, length: data.readableBytes)!
		// if (kcp[key] == nil) {
		// 	pendingIncoming[key, default: []].append(data)
		// 	return
		// }
	}
	
	// Receiving data which needs to be sent
	internal func write(context:ChannelHandlerContext, data:NIOAny, promise:EventLoopPromise<Void>?) {
		var (key, data) = unwrapOutboundIn(data)
		if (kcp[key] == nil) {
			kcp[key, default: []].append(KCPControlBlock())
			return
		}



	}
	
	func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
		switch event {
			case let evt as WireguardHandler.WireguardHandshakeNotification:
				logger.debug("Resetting kcp", metadata: ["public-key_remote":"\(evt.publicKey)"])
				// Need to figure out how to make this into a conversation id
				let key = evt.publicKey
				
			default:
				context.fireUserInboundEventTriggered(event)
				return
		}
	}
}