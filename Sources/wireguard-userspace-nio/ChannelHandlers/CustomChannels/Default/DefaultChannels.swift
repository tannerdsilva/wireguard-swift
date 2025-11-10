import NIO
import Logging

struct DefaultChannels: CustomChannels {
	
	var head: DefaultHeadChannel
	
	var tail: SplicerHandler
	
	var body: [any ChannelDuplexHandler]
	
	typealias HeadChannel = DefaultHeadChannel
	
	typealias TailChannel = SplicerHandler
	
	typealias BodyChannels = [any ChannelDuplexHandler]
	
	typealias ArgumentType = (mtuLims:MTULimits, loglevel:Logger.Level)
	
	init(_ env: ArgumentType) {
		head = DefaultHeadChannel(logLevel: env.loglevel)
		tail = SplicerHandler(logLevel: env.loglevel, spliceByteLength: env.mtuLims.mtuOutboundIn)
		body = []
	}
}
