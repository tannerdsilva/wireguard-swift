/// one of the four types of messages that can be sent in a WireGuard connection.
public enum Message {
	case handshakeInitiation
	case handshakeResponse
	case cookieResponse(Cookie.Payload)
	case data(Data.Payload)
}