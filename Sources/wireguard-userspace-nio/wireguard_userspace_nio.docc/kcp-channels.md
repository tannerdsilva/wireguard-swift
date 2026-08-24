# KCP Channels

The **KCP Channels** implement a modified version of KCP for a `WGInterface`. KCP is a UDP wrapper that provides guaranteed, in-order packet delivery on top of lossy UDP, and this channel set reimplements the original C KCP algorithm in Swift, adapted to the NIO pipeline.

- **Head Channel:** `KCPSegment.Handler` combines and splits KCP segments to and from a single MTU data packet.
- **Body Channels:** The KCP control block handler, which takes raw data from the tail channel and wraps it into a KCP segment with its associated segment header.
- **Tail Channel:** `SplicerHandler` splices outbound data according to the MTU of the pipeline.

The KCP control block itself is an internal implementation detail; the public surface of this channel set is the channel set, its segment type, and the errors the control block can raise.

## Topics

### Channel Set
- ``KCPChannels``

### Segment
- ``KCPSegment``
- ``KCPSegment/Handler``

### Tail Channel
- ``SplicerHandler``

### Errors
- ``SendError``
- ``ReceiveError``
- ``InputError``
