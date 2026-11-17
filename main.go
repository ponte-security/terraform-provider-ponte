// Command terraform-provider-ponte manages Ponte resources (policies, agent groups, bindings)
// from Terraform, through the control plane's operator API.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/ponte-ai/terraform-provider-ponte/internal/provider"
)

// version is set by the release build (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers (delve)")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/ponte-ai/ponte",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
