import NIO
import Logging
import RAW
import RAW_dh25519

struct KCPChannels: CustomChannels {
	
	var head: KCPSegment.Handler
	
	var tail: SplicerHandler
	
	var body: [any ChannelDuplexHandler]
	
	typealias HeadChannel = KCPSegment.Handler
	
	typealias TailChannel = SplicerHandler
	
	typealias BodyChannels = [any ChannelDuplexHandler]
	
	typealias ArgumentType = (privateKey:MemoryGuarded<PrivateKey>, mtuLims:MTULimits, loglevel:Logger.Level)
	
	init(_ env: ArgumentType) {
		var mtuLimsCpy = env.mtuLims
		head = KCPSegment.Handler(privateKey:env.privateKey, mtu:&mtuLimsCpy, logLevel:env.loglevel)
		body = [KCPControlBlock.Handler(key:env.privateKey, mtu:&mtuLimsCpy, logLevel:env.loglevel)]
		tail = SplicerHandler(logLevel:env.loglevel, spliceByteLength: 50_000)
	}
}
