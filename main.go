package main

import (
	"bufio"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	state := newAppState()

	clearTerminal()
	printWelcome()
	state.loadSubscription(reader)

	for {
		server, ok := selectServer(reader, state)
		if !ok {
			return
		}

		if handleServerActions(reader, state, server) {
			return
		}
	}
}
