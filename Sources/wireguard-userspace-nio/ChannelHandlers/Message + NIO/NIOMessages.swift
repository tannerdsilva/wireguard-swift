import NIO
import RAW_dh25519
import RAW_xchachapoly
import Logging
import RAW
import wireguard_crypto_core
import Synchronization
import bedrock

extension Message {
	internal enum NIO {
		case initiation(Initiation.Payload.Authenticated)
		case response(Response.Payload.Authenticated)
		case cookie(Cookie.Payload)
		case data(Data.Payload.NIO)
	}
}

extension Message.Cookie.Payload {
	internal struct NIO {
		
	}
}

extension Message.Data.Payload {
	internal struct NIO {
		internal let header:Message.Data.Header
		internal let data:ByteBufferView
	}
}

