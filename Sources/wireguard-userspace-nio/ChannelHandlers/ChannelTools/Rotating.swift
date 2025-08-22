internal struct Rotating<Element> {
	internal private(set) var previous:Element? = nil
	internal private(set) var current:Element? = nil
	internal private(set) var next:Element? = nil
	
	internal init(previous pIn:Element?, current cIn:Element?, next nIn:Element?) {
		previous = pIn
		current = cIn
		next = nIn
	}
}
