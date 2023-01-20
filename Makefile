SHELL := /bin/bash

.PHONY: build format test

build:
	env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" lib.go

format:
	gofmt -s -w -l .

test:
	go test ./...
