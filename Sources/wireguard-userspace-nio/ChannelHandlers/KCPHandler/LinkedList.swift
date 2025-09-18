/// A minimal doubly‑linked list that behaves like the C i‑queue used by KCP.
/// - NOTE: All public operations are O(1).
public struct LinkedList<Element> {
	public final class Node {
		/// The payload – `nil` only for the sentinel.
		public var value:Element?
		public var next:Node!
		public var prev:Node!
		init(value: Element? = nil) {
			self.value = value
			self.next = self
			self.prev = self
		}
	}

	private let head:Node
	public private(set) var count:UInt32 = 0
	public init() {
		head = Node(value: nil)               // sentinel
	}
	public typealias Handler = (Node, Element)
	public var isEmpty:Bool { head.next === head }
	public var front:Node? { isEmpty ? nil : head.next }
	public var back:Node? { isEmpty ? nil : head.prev }
	public mutating func add(_ node:Node) { insert(node, after: head) }
	public mutating func addTail(_ node:Node) { insert(node, before: head) }
	public mutating func remove(_ node:Node) {
		let p = node.prev!
		let n = node.next!
		p.next = n
		n.prev = p

		node.next = nil
		node.prev = nil
		count -= 1
	}
	
	private static func makeNode(_ element: Element) -> Node {
		return Node(value: element)
	}

	public mutating func popFront() -> Element? {
		guard let n = front else { return nil }
		let v = n.value!
		remove(n)
		return v
	}

	public mutating func popBack() -> Element? {
		guard let n = back else { return nil }
		let v = n.value!
		remove(n)
		return v
	}
	public mutating func clear() {
		// break the links on every node
		var cur = head.next!
		while cur !== head {
			let nxt = cur.next!
			cur.next = nil
			cur.prev = nil
			cur = nxt
		}
		// make sentinel point to itself again
		head.next = nil
		head.prev = nil
		count = 0
	}
	private mutating func insert(_ node: Node, after anchor: Node) {
		let nxt = anchor.next!
		node.next = nxt
		node.prev = anchor
		anchor.next = node
		nxt.prev = node
		count += 1
	}
	private mutating func insert(_ node: Node, before anchor: Node) {
		insert(node, after: anchor.prev!)
	}
}

extension LinkedList {
	@discardableResult public mutating func add(_ element:Element) -> Node {
		let newNode = Self.makeNode(element)
		add(newNode)
		return newNode
	}
	@discardableResult public mutating func addTail(_ element:Element) -> Node {
		let newNode = Self.makeNode(element)
		addTail(newNode)
		return newNode
	}
	@discardableResult public mutating func insert(_ element:Element, after anchor:Node) -> Node {
		let newNode = Self.makeNode(element)
		insert(newNode, after:anchor)
		return newNode
	}
}

extension LinkedList: Sequence {
	public struct Iterator:IteratorProtocol, Sequence {
		// The node that will be returned on the next call to `next()`.
		private var nextNode: LinkedList<Element>.Node?
		// Sentinel node that marks the end of the list.
		private let sentinel: LinkedList<Element>.Node

		init(start: LinkedList<Element>.Node?, sentinel: LinkedList<Element>.Node) {
			self.nextNode = start			// start at the real head (or nil)
			self.sentinel = sentinel   		// the dummy head that points to itself
		}

		public mutating func next() -> (Node, Element)? {
			// Stop when we hit the sentinel again.
			guard let node = nextNode, node !== sentinel else { return nil }

			// Advance *before* returning so that removal of `node` does not corrupt our iteration.
			nextNode = node.next

			return (node, node.value!)
		}
		
		public func current() -> (Node, Element)? {
			// Stop when we hit the sentinel again.
			guard let node = nextNode, node !== sentinel else { return nil }

			return (node, node.value!)
		}
	}

	public func makeIterator() -> Iterator {
		return Iterator(start: front, sentinel: head)
	}
	
	public func makeLoopingIterator() -> Iterator {
		return Iterator(start: head, sentinel: head)
	}
	
	public func makeReverseIterator() -> ReversedIterator {
		return ReversedIterator(start:back, sentinel:head)
	}
	
	public struct ReversedIterator:IteratorProtocol, Sequence {
		/// The node that will be returned on the next call to `next()`.
		private var nextNode: LinkedList<Element>.Node?
		/// Sentinel node that marks the end of the list.
		private let sentinel:LinkedList<Element>.Node

		/// Create a new iterator.
		///
		/// - Parameters:
		///   - start:   The node that should be returned first – typically `back`.
		///   - sentinel: The dummy head node (`head`) that points to itself.
		init(start: LinkedList<Element>.Node?, sentinel: LinkedList<Element>.Node) {
			self.nextNode = start
			self.sentinel = sentinel
		}

		/// Advance the iterator and return the next `(node, value)` pair.
		///
		/// The iterator assumes that the user may delete the *currently*
		/// returned node.  To avoid corruption it stores `node.prev`
		/// **before** returning the pair, because `remove(_:)` sets a
		/// removed node’s `prev` and `next` to itself.
		///
		/// - Returns: `(Node, Element)` if there is a next element, otherwise `nil`.
		public mutating func next() -> (Node, Element)? {
			// Stop when we hit the sentinel again.
			guard let node = nextNode, node !== sentinel else { return nil }

			// Advance *before* returning so that removal of `node`
			// (which sets node.prev = node) does not corrupt our
			// iteration.
			nextNode = node.prev

			return (node, node.value!)
		}
	}
}

extension LinkedList.Iterator {
	/// Returns an iterator that would start at the node **after**
	/// the element that this iterator will return on its next
	/// call.  If the current iterator is already at the end,
	/// `nil` is returned.
	///
	/// Example:
	///     var it = list.makeIterator()
	///     if let nextIt = it.nextIterator() { … }
	///
	/// - Returns: a new iterator positioned after the current
	///            element, or `nil` when there is no next node.
	public func nextIterator() -> LinkedList.Iterator? {
		// If this iterator has no element to return, we're at the end.
		let current = self.nextNode
		guard current!.next !== nil else {
			return nil
		}

		// The node that would be returned by `next()`
		let nodeThatWouldBeReturned = current

		// The node *after* that one
		let nextNode = nodeThatWouldBeReturned!.next

		// If nextNode is the sentinel, the list is exhausted.
		return LinkedList.Iterator(start: nextNode, sentinel: sentinel)
	}
	/// Returns an iterator that would start at the node **before**
	/// the element this iterator would return on its next call.
	///
	/// • If the iterator is already exhausted (`currentNode == nil`) or
	///   the list is empty, `nil` is returned.
	///
	/// The original iterator is **not** mutated.
	///
	/// - Returns: a new iterator positioned at the preceding node,
	///            or `nil` if no such node exists.
	public func prevIterator() -> LinkedList.Iterator? {
		// 1. If this iterator has nothing left, we’re at the end.
		let current = self.nextNode
		guard current!.prev !== nil else {
			return nil
		}
		
		// 2. The node that `next()` would return now
		let nodeThatWouldBeReturned = current
		
		// 3. The node *before* that one
		let prevNode = nodeThatWouldBeReturned!.prev
		
		// 4. If we’d hit the sentinel (or an empty list) we’re done.
		return LinkedList.Iterator(start: prevNode, sentinel: sentinel)
	}
}