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

	for {
		if handleMainMenu(reader, state) {
			return
		}
	}
}
