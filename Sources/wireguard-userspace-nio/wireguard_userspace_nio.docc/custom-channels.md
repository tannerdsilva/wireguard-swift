# Custom Channels

Custom channels are pluggable, self-contained sets of NIO `ChannelDuplexHandler` instances that sit between data encryption and data handoff in a `WGInterface` pipeline. Each channel set conforms to the `CustomChannels` protocol and is composed of three parts:

- A **head channel** that communicates with the `WireguardHandler` and defines the interface between the WireGuard layer and your channel set.
- **Body channels** that process data between the head and tail channels.
- A **tail channel** that communicates with the `DataHandoffHandler`.

The channels connect in the following order:

```
head -> body[0] -> ... -> body[n-1] -> tail
```

It is the responsibility of the channel set to keep the inbound and outbound types aligned between its handlers.

## Topics

### Framework
- ``CustomChannels``
- ``PeerAssociated``
- ``PeerAssociatedHeadHandler``
- ``PeerAssociatedTailHandler``

### Default Channels
- <doc:default-channels>

### KCP Channels
- <doc:kcp-channels>

### Keep Alive Channels
- <doc:keep-alive-channels>

### Supporting Types
- ``MTULimits``
