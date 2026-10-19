// Command tenarium runs the Tenarium server with all built-in plugins.
package main

import (
	"github.com/AimTune/tenarium/pkg/server"
	_ "github.com/AimTune/tenarium/plugins/all"
)

func main() { server.Main() }
