# Default Channels

The **Default Channels** are a minimal custom channel set for a `WGInterface` when no data transformation is required. Inbound and outbound data passes through the pipeline untouched, and outbound packets are spliced to the MTU before leaving the channel set.

- **Head Channel:** `DefaultHeadChannelHandler` passes inbound and outbound data to the next handler unchanged.
- **Body Channels:** None.
- **Tail Channel:** `SplicerHandler` splices outbound data according to the MTU of the pipeline.

## Topics

### Channel Set
- ``DefaultChannels``

### Head Channel
- ``DefaultHeadChannelHandler``

### Tail Channel
- ``SplicerHandler``
