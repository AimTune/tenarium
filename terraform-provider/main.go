// Command terraform-provider-tenarium is the Terraform provider for the
// Tenarium multi-tenant control plane.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/AimTune/tenarium/terraform-provider/internal/provider"
)

// version is set by the release build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/aimtune/tenarium",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
