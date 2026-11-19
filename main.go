package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/pderuiter/terraform-provider-pf/internal/provider"
)

// Set by GoReleaser / CI via -ldflags.
var version = "dev"

//go:generate sh -c "cd tools && go tool tfplugindocs generate --provider-dir .. --provider-name pf"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/pderuiter/pf",
		Debug:   debug,
	}
	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
