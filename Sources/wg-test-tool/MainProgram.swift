import ArgumentParser

@main
struct CLI:ParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wg-test-tool",
		abstract:"a development tool to aid in the development of the wireguard-userspace-nio target (and others).",
		subcommands:[
		
		]
	)
    // add run func
}

// Create client and server struct with subcommands
