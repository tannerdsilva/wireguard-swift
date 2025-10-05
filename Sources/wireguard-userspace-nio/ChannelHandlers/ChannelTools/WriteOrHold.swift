import NIO
import Logging

internal protocol LenghExpressibleExchangeType:Sendable {
	/// the length of the type when encoded into a ByteBuffer
	var bytesOnWire:Int { get }
}

internal struct WriteOrHold<ExchangedType:LenghExpressibleExchangeType>:Sendable {
	/// used to express the result of a holdOrWrite operation.
	internal enum Result:Sendable {
		/// indicates that the message was held due to backpressure, and specifies the number of messages currently being held.
		case held(messages:Int)
		/// indicates that the message was written immediately
		case written
		/// indicates that the message was dropped due to exceeding the item limit.
		case limitExceeded
	}

	/// thrown when the item limit is exceeded.
	internal struct ItemLimitExceededError:Swift.Error, Sendable {}
		
	/// the logger for this driver
	private let log:Logger

	/// the amount of items that can be held before the driver starts dropping items.
	private let limit:Int

	/// the array that stores the pending messages and their write promises if there is any backpressure on the channel.
	private var pendingMessages:[(ExchangedType, EventLoopPromise<Void>?)]

	/// creates a new WriteOrHold driver with the specified log level.
	internal init(logLevel:Logger.Level, limit:Int = 1024) {
		pendingMessages = []
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger[metadataKey:"exchanged_type"] = "\(String(describing:ExchangedType.self))"
		buildLogger.logLevel = logLevel
		log = buildLogger
		pendingMessages.reserveCapacity(limit)
		self.limit = limit
	}
	internal mutating func writabilityChanged<CH>(context:borrowing ChannelHandlerContext, handler:borrowing CH) where CH:ChannelOutboundHandler, CH.OutboundOut == ExchangedType {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		if context.channel.isWritable {
			log.trace("channel is now writable. now writing \(pendingMessages.count) pending messages.")
			let allMessages = pendingMessages
			pendingMessages.removeAll(keepingCapacity:true)
			for message in allMessages {
				holdOrWrite(context: context, handler: handler, message.0, writePromise: message.1)
			}
		}
	}

	@discardableResult internal mutating func holdOrWrite<CH>(context:borrowing ChannelHandlerContext, handler:borrowing CH, _ message:ExchangedType, writePromise:EventLoopPromise<Void>?) -> Result where CH:ChannelOutboundHandler, CH.OutboundOut == ExchangedType {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		if context.channel.isWritable {
			context.write(handler.wrapOutboundOut(message), promise:writePromise)
			return .written
		} else {
			guard pendingMessages.count < limit else {
				log.warning("write limit reached, dropping message.", metadata:["held_messages":"\(pendingMessages.count)"])
				writePromise?.fail(ItemLimitExceededError())
				return .limitExceeded
			}
			pendingMessages.append((message, writePromise))
			log.trace("channel is not writable, holding message. currently holding \(pendingMessages.count) messages.", metadata:["held_messages":"\(pendingMessages.count)"])
			return .held(messages:pendingMessages.count)
		}
	}
}