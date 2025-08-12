/// one of the four types of messages that can be sent in a WireGuard connection.
public enum Message:Sendable {
	case initiation(Initiation.Payload.Authenticated)
	case response(Response.Payload.Authenticated)
	case cookie(Cookie.Payload)
	case data(Data.Payload)
}