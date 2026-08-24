# Keep Alive Channels

The **Keep Alive Channels** are a custom channel set for a `WGInterface` whose sole purpose is to keep the interface handshaking with its peers. They send empty keep-alive packets to each configured peer and drop all data traffic, so they are only appropriate for connections that exchange no application data (or where data is supplied by another channel set).

- **Head Channel:** `KeepAliveHandler` schedules a repeated task that sends an empty keep-alive packet to each peer.
- **Body Channels:** None.
- **Tail Channel:** `DropAllHandler` drops every inbound and outbound packet.

## Topics

### Channel Set
- ``KeepAlive``

### Head Channel
- ``KeepAliveHandler``

### Tail Channel
- ``DropAllHandler``

### Peer Configuration
- ``PeerInfo``
