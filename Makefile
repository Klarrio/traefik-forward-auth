.PHONY: format
format:
	gofmt -w -s *.go

.PHONY: test
test:
	go test -v .