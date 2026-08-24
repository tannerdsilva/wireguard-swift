import NIO

/// A container that passes a `ChannelHandlerContext` to repeated tasks.
///
/// `ChannelHandlerContext` is not `Sendable`, so this wrapper is an
/// `unchecked Sendable` to communicate that the context is used in a thread-safe
/// manner.
public final class ContextContainer:@unchecked Sendable {
	/// The context that the container instance is holding.
	private let context:ChannelHandlerContext
	
	/// Initializes a context container with the given context.
	/// - Parameter ctx: The context to be held by this container.
	public init(context ctx:ChannelHandlerContext) {
		context = ctx
	}
	
	/// The only way to access the context, ensuring it is accessed in a
	/// thread-safe manner.
	/// - Parameter body: A closure receiving a pointer to the context.
	/// - Returns: Whatever `body` returns.
	/// - Throws: Whatever `body` throws.
	public borrowing func accessContext<E, R>(_ body:(UnsafePointer<ChannelHandlerContext>) throws(E) -> R) throws(E) -> R where E:Swift.Error{
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		return try withUnsafePointer(to:context) { (ptrArg:UnsafePointer<ChannelHandlerContext>) throws(E) -> R in
			try body(ptrArg)
		}
	}
}
