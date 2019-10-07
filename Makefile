DOCKER_NAMESPACE?=klarrio-docker.jfrog.io/tools
DOCKER_TAG?=latest

.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o ./traefik-forward-auth-linux .

.PHONY: docker-image
docker-image: build-linux
	docker build -t $(DOCKER_NAMESPACE)/traefik-forward-auth:${DOCKER_TAG} .

.PHONY: format
format:
	gofmt -w -s *.go

.PHONY: test
test:
	go test -v .