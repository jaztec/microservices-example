# Project information
VERSION? := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename "$(PWD)")

# Go build variables
GOBASE := $(shell pwd)
GOPATH := $(GOBASE)/vendor:$(GOBASE)
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard *.go)

CMD := $(GOBASE)/cmd

# Linker flags
LDFLAGS=-v -ldflags "-s -w -X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

.PHONY: all build clean lint

all: build

build:  ## Build the binary file
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -mod mod $(LDFLAGS) -v -o $(GOBIN)/api_service $(CMD)/api_service
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -mod mod $(LDFLAGS) -v -o $(GOBIN)/auth_service $(CMD)/auth_service
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -mod mod $(LDFLAGS) -v -o $(GOBIN)/user_service $(CMD)/user_service
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -mod mod $(LDFLAGS) -v -o $(GOBIN)/client_service $(CMD)/client_service
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -mod mod $(LDFLAGS) -v -o $(GOBIN)/ca_service $(CMD)/ca_service

test: ## Test the library
	@mkdir -p artifacts/profiles
	go test ./... -bench=. -race -timeout 10000ms -coverprofile cover.out
	go tool cover -func=cover.out

proto-gen: ## Generate protobuf files
	@protoc --go_out=./proto --go_opt=paths=source_relative --go-grpc_out=./proto --go-grpc_opt=paths=source_relative --proto_path=./proto proto/*.proto

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
