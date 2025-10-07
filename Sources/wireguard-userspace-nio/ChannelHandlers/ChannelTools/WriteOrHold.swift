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
	private let limit:Int?
	/// the array that stores the pending messages and their write promises if there is any backpressure on the channel.
	private var pendingMessages:[(ExchangedType, EventLoopPromise<Void>?)]

	/// creates a new WriteOrHold driver with the specified log level.
	internal init(logLevel:Logger.Level, limit:Int?) {
		pendingMessages = []
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger[metadataKey:"exchanged_type"] = "\(String(describing:ExchangedType.self))"
		buildLogger.logLevel = logLevel
		log = buildLogger
		if limit != nil {
			pendingMessages.reserveCapacity(limit!)
		}
		self.limit = limit
	}

	internal mutating func writabilityChanged<CH>(context:borrowing ChannelHandlerContext, handler:borrowing CH) where CH:ChannelOutboundHandler, CH.OutboundOut == ExchangedType {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		var removed = 0
		while context.channel.isWritable == true && pendingMessages.isEmpty == false {
			let message = pendingMessages.removeFirst()
			context.write(handler.wrapOutboundOut(message.0), promise:message.1)
			removed += 1
		}
		if removed > 0 {
			log.debug("channel is writable...flushing \(removed) messages.", metadata:["remaining_held_messages":"\(pendingMessages.count)"])
			context.flush()
		} else {
			log.trace("channel is writable, but no held messages to flush.", metadata:["remaining_held_messages":"\(pendingMessages.count)"])
		}
	}

	@discardableResult internal mutating func holdOrWrite<CH>(context:borrowing ChannelHandlerContext, handler:borrowing CH, _ message:ExchangedType, writePromise:EventLoopPromise<Void>?) -> Result where CH:ChannelOutboundHandler, CH.OutboundOut == ExchangedType {
		#if DEBUG
		context.eventLoop.assertInEventLoop()
		#endif
		if true || context.channel.isWritable {
			context.write(handler.wrapOutboundOut(message), promise:writePromise)
			return .written
		} else {
			guard limit == nil || pendingMessages.count < limit! else {
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
