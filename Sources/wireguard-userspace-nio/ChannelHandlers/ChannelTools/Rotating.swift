internal struct Rotating<Element> {
	internal private(set) var previous:Element?
	internal private(set) var current:Element?
	internal private(set) var next:Element?
	internal init() {
		previous = nil
		current = nil
		next = nil
	}
	internal init(current cIn:Element) {
		previous = nil
		current = cIn
		next = nil
	}
	internal init(next nIn:Element) {
		previous = nil
		current = nil
		next = nIn
	}
	internal init(previous pIn:Element?, current cIn:Element?, next nIn:Element?) {
		previous = pIn
		current = cIn
		next = nIn
	}
	
	/// apply next element
	@discardableResult internal mutating func apply(next nextElement:Element?) -> Element? {
		defer {
			next = nextElement
		}
		return next
	}
	
	
	/// rotates the trio of stored instances. previous is assigned the current value. current is assigned the next value. next value is assigned nil.
	/// - returns: the previous (outgoing) instance that was replaced with the current value.
	@discardableResult internal mutating func rotate() -> Element? {
		defer {
			previous = current
			current = next
			next = nil
		}
		return previous
	}
	
	/// rotates the trio of stored instances. previous is assigned the current value. current is assigned the next value. next value is assigned nil.
	/// - parameters:
	/// 	- replacingNext: the element to assign to the `next` position prior to the rotation transformation is applied.
	/// - returns: the previous (outgoing) instance that was replaced with the current value.
	@discardableResult internal mutating func rotate(replacingNext nextCurrent:Element) -> Element? {
		defer {
			previous = current
			current = nextCurrent
			next = nil
		}
		return previous
	}
}
