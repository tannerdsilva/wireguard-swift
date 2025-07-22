import ArgumentParser
import wireguard_userspace_nio

@main
struct CLI:ParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wg-test-tool",
		abstract:"a development tool to aid in the development of the wireguard-userspace-nio target (and others).",
		subcommands:[
            
		]
	)
    func run() throws {
    }
}

// Create client and server struct with subcommands
