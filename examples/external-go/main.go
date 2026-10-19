// Command external-go runs the guard example as an external plugin:
//
//	plugins:
//	  - plugin: external
//	    name: guard
//	    config:
//	      command: ["go", "run", "./examples/external-go"]
//	      config: {forbidden_prefix: "test-"}
package main

import (
	"log"

	"github.com/AimTune/tenarium/examples/external-go/guard"
	"github.com/AimTune/tenarium/pkg/extplugin"
)

func main() {
	if err := extplugin.Serve(&guard.Plugin{}); err != nil {
		log.Fatal(err)
	}
}
