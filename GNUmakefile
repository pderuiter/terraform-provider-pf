default: fmt lint build test

build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

# Regenerate docs/ from the schemas, examples/ and templates/. CI fails when
# the committed docs differ from the generated ones.
generate:
	go generate ./...

fmt:
	gofmt -s -w -e .
	terraform fmt -recursive ./examples/

test:
	go test -v -cover -race -timeout=120s ./...

# Provider acceptance tests against the in-process fake pfapid (needs only
# a terraform binary). TestAccLab also runs when PFAPID_ENDPOINT,
# PFAPID_CA_CERT, PFAPID_CLIENT_CERT and PFAPID_CLIENT_KEY point at a lab
# firewall.
testacc:
	TF_ACC=1 go test ./internal/provider/ -v -count=1 -timeout 30m

.PHONY: default build install lint generate fmt test testacc
