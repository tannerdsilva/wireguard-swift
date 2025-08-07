import NIO

/// used to pass ChannelHandlerContext to repeated tasks. ChannelHandlerContext is not Sendable, so we use a container that is unchecked Sendable to communicate to the compiler that the channel handler context is being used in a thread-safe manner.
internal final class ContextContainer:@unchecked Sendable {
	private let context:ChannelHandlerContext
	internal init(context ctx:ChannelHandlerContext) {
		context = ctx
	}
	/// the only way to access the context is through this function, which ensures that the context is accessed in a thread-safe manner.
	internal borrowing func accessContext(_ body:(UnsafePointer<ChannelHandlerContext>) -> Void) {
		#if DEBUG
		context.eventLoop.assertInEventLoop() 
		#endif
		withUnsafePointer(to:context) {
			body($0)
		}
	}
}