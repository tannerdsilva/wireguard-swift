/// One of the four message types that can be sent in a WireGuard connection.
public enum Message:Sendable {
	/// A handshake initiation message.
	case initiation(Initiation.Payload.Authenticated)
	/// A handshake response message.
	case response(Response.Payload.Authenticated)
	/// A cookie reply message.
	case cookie(Cookie.Payload)
	/// A transport data message.
	case data(Data.Payload)
}
