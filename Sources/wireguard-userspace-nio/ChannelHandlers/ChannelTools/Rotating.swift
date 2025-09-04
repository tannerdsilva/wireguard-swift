internal struct Rotating<Element> {
	/// used to express a particular value that was found at a specific position.
	internal enum Positioned {
		case previous(Element)
		case current(Element)
		case next(Element)
		internal var element:Element {
			switch self {
				case .previous(let e): return e
				case .current(let e): return e
				case .next(let e): return e
			}
		}
	}
	internal var previous:Element?
	internal var current:Element?
	internal var next:Element?
	
	/// initialize a rotating value with no content (`nil` assigned to all 3 stored variables)
	internal init() {
		previous = nil
		current = nil
		next = nil
	}
	
	/// initialize a rotating value with the specified `current` value
	internal init(current cIn:Element) {
		previous = nil
		current = cIn
		next = nil
	}
	
	/// initialize a rotating value with the specified `next` value
	internal init(next nIn:Element) {
		previous = nil
		current = nil
		next = nIn
	}
	
	/// initialize a rotating value with explicit assignments for all three stored variables in the rotational structure.
	internal init(previous pIn:Element?, current cIn:Element?, next nIn:Element?) {
		previous = pIn
		current = cIn
		next = nIn
	}
	
	/// apply next element without applying a rotational transformation.
	/// - returns: the previous (outgoing) instance that was replaced with the current value.
	internal mutating func apply(next nextElement:Element?) -> Element? {
		defer {
			next = nextElement
		}
		return next
	}
	
	
	/// rotates the trio of stored instances. previous is assigned the current value. current is assigned the next value. next value is assigned nil.
	/// - returns: the previous (outgoing) instance that was replaced with the current value.
	internal mutating func rotate() -> Element? {
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
	internal mutating func rotate(replacingNext nextCurrent:Element) -> (previous:Element?, next:Element?) {
		defer {
			previous = current
			current = nextCurrent
			next = nil
		}
		return (previous, next)
	}
}

extension Rotating:CustomDebugStringConvertible where Element:CustomDebugStringConvertible {
	internal var debugDescription:String {
		return "(previous:\(String(describing:previous)), current:\(String(describing:current)), next:\(String(describing:next)))"
	}
}