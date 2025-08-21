internal struct Rotating<Element> {
	internal var previous:Element? = nil
	internal var current:Element? = nil
	internal var next:Element? = nil
	
	internal init(previous pIn:Element?, current cIn:Element?, next nIn:Element?) {
		previous = pIn
		current = cIn
		next = nIn
	}
}
